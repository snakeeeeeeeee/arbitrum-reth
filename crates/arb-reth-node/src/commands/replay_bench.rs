//! `arb-reth replay-bench`: re-execute recorded sequencer-feed messages against a node datadir
//! (read-only) and time block production with the MEV transaction-log stream attached.
//!
//! Every produced block is compared with the canonical block stored in the datadir; any mismatch
//! is reported and makes the command exit non-zero.
//!
//! - `--verify-state-root`: the full block hash is compared. It commits to the state root, the
//!   receipts root (status, cumulative gas, logs) and the transactions root, so a match proves that
//!   execution is bit-for-bit unchanged for that block. The root is computed serially against a
//!   historical provider (seconds per block).
//! - default (timing mode): the state root is skipped; receipts root, transactions root, logs bloom
//!   and gas used are compared.
//!
//! State is read through Reth's historical provider at `N - 1`, fronted by a per-block read cache
//! that the first run fills and later runs hit (like the live node's cross-block cache). There is
//! no sparse state-root task. Compare builds on the same datadir, messages and machine.
//!
//! Research additions (branch research/bigblock-0924, not used by the live node):
//! - `--synth-from-db`: rebuild each block's sequencer message from the canonical block in the
//!   datadir (user transactions + the start-block call arguments). The receipts/transactions root
//!   check still proves the rebuilt message is equivalent. Blocks that did not come from a plain
//!   sequencer L2 message (delayed inbox, batch-posting report) are skipped.
//! - `--live-cache-mb`: one execution cache shared across consecutive blocks and advanced with
//!   every executed block, like the live engine tree. Reads that miss it are counted and timed.
//! - `--tx-detail`: per-transaction `[to, selector, gas, us]` in the JSON output.

use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::ArbNode;
use alloy_primitives::{Address, Bytes};
use alloy_consensus::TxReceipt as _;
use alloy_eips::{Encodable2718 as _, Typed2718 as _};
use arb_reth_engine::{
    ArbMissStats, ArbReexecCache, ArbReexecOptions, ArbTxExecutionKind, ArbTxLogBroadcaster,
    reexecute_message_ext,
};
use arb_revm::{constants::ARBOS_STATE_ADDRESS, storage::read_serialized_chain_config};
use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;
use clap::Parser;
use metrics::{
    Counter, Gauge, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use reth_db_api::models::StorageSettings;
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::SealedHeader;
use reth_provider::providers::{ProviderFactoryBuilder, ReadOnlyConfig};
use reth_provider::{
    BlockNumReader, BlockReader, HeaderProvider, ReceiptProvider, StateProvider,
    StorageSettingsCache,
};

/// Re-execute recorded feed messages against a datadir and time block production.
#[derive(Debug, Parser)]
#[command(name = "replay-bench", about = "Re-execute recorded feed messages and time production")]
pub struct ReplayBenchArgs {
    /// Node datadir (opened read-only; the node may keep running).
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// NDJSON file with one `BroadcastFeedMessage` per line (the feed's `messages[]` items).
    /// Not needed with `--synth-from-db`.
    #[arg(long, value_name = "PATH")]
    feed: Option<PathBuf>,

    /// Rebuild each block's sequencer message from the canonical block in the datadir instead of
    /// reading `--feed` (requires `--from` and `--to`).
    #[arg(long)]
    synth_from_db: bool,

    /// Only time blocks with at least this many user transactions (ignored with
    /// `--live-cache-mb`, which must execute every block to keep its cache consistent).
    #[arg(long, default_value_t = 0)]
    min_txs: usize,

    /// Live-like cross-block execution cache of this many MiB, shared by consecutive blocks and
    /// advanced with each executed block. Forces `--repeat 1`. Cache misses are counted and timed.
    #[arg(long, default_value_t = 0)]
    live_cache_mb: usize,

    /// Re-read every missed storage slot through the *latest* provider and report that time
    /// (estimates the live node's miss cost; only with `--live-cache-mb`).
    #[arg(long)]
    retime_misses: bool,

    /// Include `[to, selector, gas, us]` per executed transaction in the JSON output.
    #[arg(long)]
    tx_detail: bool,

    /// Research (live-like mode with `--synth-from-db` only): emulate a prewarm task. This many
    /// threads each execute a strided slice of the block's user transactions on the parent state
    /// through the shared cache (results discarded, cache filled on miss), concurrently with the
    /// timed serial execution. They are stopped and joined before the block's changes advance the
    /// cache, so no stale pre-state value can be inserted afterwards.
    #[arg(long, default_value_t = 0)]
    prewarm_threads: usize,

    /// Arbitrum chain id.
    #[arg(long, default_value_t = 4663)]
    chain_id: u64,

    /// L2 block of message index 0 (block = sequence number + genesis block).
    #[arg(long, default_value_t = 0)]
    genesis_block: u64,

    /// Only blocks at or above this number.
    #[arg(long)]
    from: Option<u64>,

    /// Only blocks at or below this number.
    #[arg(long)]
    to: Option<u64>,

    /// Stop after this many blocks.
    #[arg(long)]
    max_blocks: Option<usize>,

    /// Executions per block; the timing of the last one is reported (earlier runs warm caches).
    /// Every run is checked against the canonical hash.
    #[arg(long, default_value_t = 2)]
    repeat: usize,

    /// Do not attach the MEV transaction-log stream (measures the stream's own overhead).
    #[arg(long)]
    no_stream: bool,

    /// Attach the stream with frontier retention off (`--mev-tx-log-frontiers=false`).
    #[arg(long)]
    no_frontiers: bool,

    /// Compute the state root and compare full block hashes (slow). Default compares receipts
    /// root, transactions root, logs bloom and gas used.
    #[arg(long)]
    verify_state_root: bool,

    /// Also publish the early kind-4 manifest for every block (as the feed coordinator does with
    /// `--mev-tx-log-early-feed-txs`), time its decode, and check that its entries equal the
    /// engine's late manifest for the same block.
    #[arg(long)]
    early: bool,

    /// Per-block parent-state read cache in MiB (0 disables).
    #[arg(long, default_value_t = 64)]
    cache_mb: usize,

    /// Write one JSON line per block here.
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

/// Captures samples of the `arb_reth.mev.*` histograms so per-transaction timings can be reported.
#[derive(Clone, Default)]
struct SampleRecorder {
    samples: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

struct SampleSink {
    name: String,
    samples: Arc<Mutex<HashMap<String, Vec<f64>>>>,
}

impl HistogramFn for SampleSink {
    fn record(&self, value: f64) {
        if let Ok(mut samples) = self.samples.lock() {
            samples.entry(self.name.clone()).or_default().push(value);
        }
    }
}

impl Recorder for SampleRecorder {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, _: &Key, _: &Metadata<'_>) -> Counter {
        Counter::noop()
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
        if key.name().starts_with("arb_reth.mev.") {
            Histogram::from_arc(Arc::new(SampleSink {
                name: key.name().to_string(),
                samples: Arc::clone(&self.samples),
            }))
        } else {
            Histogram::noop()
        }
    }
}

impl SampleRecorder {
    fn take(&self, name: &str) -> Vec<f64> {
        self.samples
            .lock()
            .ok()
            .and_then(|mut samples| samples.remove(name))
            .unwrap_or_default()
    }

    fn clear(&self) {
        if let Ok(mut samples) = self.samples.lock() {
            samples.clear();
        }
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[rank.min(sorted.len() - 1)]
}

fn summarize(name: &str, mut values: Vec<f64>) {
    values.sort_by(|a, b| a.total_cmp(b));
    let mean = if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    };
    println!(
        "{name:<28} n={:<7} mean={:>9.1} p50={:>9.1} p90={:>9.1} p99={:>9.1} max={:>9.1}",
        values.len(),
        mean,
        percentile(&values, 50.0),
        percentile(&values, 90.0),
        percentile(&values, 99.0),
        values.last().copied().unwrap_or(0.0),
    );
}

fn us(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e6
}

/// The sequencer's feed-message sender (`0xA4B0…"sequencer"`).
const SEQUENCER_SENDER: &str = "0xa4b000000000000000000073657175656e636572";

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Rebuild the sequencer message that produced `block` from the canonical block. Returns `None`
/// for blocks that did not come from a plain sequencer L2 message.
fn synth_message(
    block: &arbitrum_alloy_consensus::reth::ArbBlock,
    number: u64,
    genesis_block: u64,
) -> Option<BroadcastFeedMessage> {
    synth_message_subset(block, number, genesis_block, None)
}

/// Like [`synth_message`], but when `keep` is given only the user transactions whose position
/// (0-based among the block's non-internal transactions) is listed are carried. Research only:
/// used to emulate prewarm workers that execute a slice of the block on the parent state.
fn synth_message_subset(
    block: &arbitrum_alloy_consensus::reth::ArbBlock,
    number: u64,
    genesis_block: u64,
    keep: Option<&[usize]>,
) -> Option<BroadcastFeedMessage> {
    use alloy_consensus::Transaction as _;
    let txs = &block.body.transactions;
    let start = txs.first()?;
    if start.ty() != 0x6a {
        return None;
    }
    // startBlock(uint256 l1BaseFee, uint64 l1BlockNumber, uint64 l2BlockNumber, uint64 timeLastBlock)
    let input = start.input();
    if input.len() < 4 + 32 * 4 {
        return None;
    }
    let word = |i: usize| &input[4 + 32 * i..4 + 32 * (i + 1)];
    let l1_base_fee = alloy_primitives::U256::from_be_slice(word(0));
    let l1_block_number = alloy_primitives::U256::from_be_slice(word(1)).saturating_to::<u64>();
    let mut l2 = vec![3u8];
    for (position, tx) in txs[1..].iter().enumerate() {
        if keep.is_some_and(|keep| !keep.contains(&position)) {
            if !matches!(tx.ty(), 0x00..=0x04 | 0x68) {
                return None;
            }
            continue;
        }
        match tx.ty() {
            0x00..=0x04 => {
                let encoded = tx.encoded_2718();
                l2.extend_from_slice(&((encoded.len() + 1) as u64).to_be_bytes());
                l2.push(4);
                l2.extend_from_slice(&encoded);
            }
            // Retries are scheduled during execution, not carried by the message.
            0x68 => {}
            _ => return None,
        }
    }
    let delayed_messages_read = u64::from_be_bytes(block.header.nonce.0);
    let base_fee = if l1_base_fee.is_zero() {
        serde_json::Value::from(0u64)
    } else {
        serde_json::Value::from(l1_base_fee.saturating_to::<u64>())
    };
    Some(BroadcastFeedMessage {
        sequence_number: number - genesis_block,
        message_with_meta_data: arbitrum_alloy_sequencer::sequencer::feed::MessageWithMetadata {
            l1_incoming_message: arbitrum_alloy_sequencer::sequencer::feed::L1IncomingMessage {
                header: arbitrum_alloy_sequencer::sequencer::feed::Header {
                    kind: 3,
                    sender: SEQUENCER_SENDER.to_string(),
                    block_number: l1_block_number,
                    timestamp: block.header.timestamp,
                    request_id: serde_json::Value::Null,
                    base_fee_l1: base_fee,
                },
                l2msg: base64_encode(&l2),
                legacy_batch_gas_cost: None,
                batch_data_stats: None,
            },
            delayed_messages_read,
        },
    })
}

pub fn run(args: ReplayBenchArgs) -> eyre::Result<()> {
    let recorder = SampleRecorder::default();
    metrics::set_global_recorder(recorder.clone())
        .map_err(|e| eyre::eyre!("install sample recorder: {e}"))?;

    let chain_spec: Arc<reth_chainspec::ChainSpec> = reth_chainspec::MAINNET.clone();
    let runtime = reth_tasks::Runtime::test();
    let factory = ProviderFactoryBuilder::<NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>>::default()
        .open_read_only(chain_spec, ReadOnlyConfig::from_datadir(&args.datadir), runtime)?;
    // The node persists in storage v2; read with the same adapter.
    factory.set_storage_settings_cache(StorageSettings::v2());
    let last_block = factory.provider()?.last_block_number()?;

    let max_code_size = {
        let latest = factory.latest()?;
        let serialized = read_serialized_chain_config(|slot| {
            latest
                .storage(ARBOS_STATE_ADDRESS, slot)
                .ok()
                .flatten()
                .unwrap_or_default()
        });
        crate::executor::max_code_size_from_serialized_config(&serialized)
    };
    let evm_config =
        arb_reth_evm::ArbEvmConfig::new(args.chain_id).with_max_code_size(max_code_size as usize);

    // A connected consumer, like the bot: drain events on another thread so every publish path
    // (logs clone, manifest, block tail) is active exactly as in production.
    let broadcaster = (!args.no_stream)
        .then(|| ArbTxLogBroadcaster::new().with_frontiers(!args.no_frontiers));
    let drained = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // Last manifest per (block, early) seen by the consumer.
    type Manifests = Arc<Mutex<HashMap<(u64, bool), Vec<(Address, Bytes)>>>>;
    let manifests: Manifests = Arc::default();
    if let Some(broadcaster) = broadcaster.as_ref() {
        let mut receiver = broadcaster.subscribe();
        let drained = Arc::clone(&drained);
        let manifests = Arc::clone(&manifests);
        std::thread::spawn(move || {
            loop {
                match receiver.blocking_recv() {
                    Ok(event) => {
                        drained.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if event.kind.is_feed_txs()
                            && let Ok(mut manifests) = manifests.lock()
                        {
                            let early = matches!(event.kind, ArbTxExecutionKind::FeedTxsEarly);
                            manifests.insert((event.block_number, early), event.feed_txs);
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    let mut out = args
        .out
        .as_ref()
        .map(|path| fs::File::create(path).map(std::io::BufWriter::new))
        .transpose()?;

    let live_cache = (args.live_cache_mb > 0).then(|| ArbReexecCache::new(args.live_cache_mb << 20));
    let repeat = if live_cache.is_some() { 1 } else { args.repeat.max(1) };

    let mut blocks = 0usize;
    let mut mismatches = 0usize;
    let skipped = std::cell::Cell::new(0usize);
    let mut tail_us = Vec::new();
    let mut feed_txs_us = Vec::new();
    let mut derived_us = Vec::new();
    let mut per_tx_mean_us = Vec::new();
    let mut tx_exec_us = Vec::new();
    let mut total_us = Vec::new();
    let mut early_us = Vec::new();
    let mut early_published = 0usize;
    let mut early_mismatches = 0usize;

    let mut process = |block: u64,
                       msg: BroadcastFeedMessage,
                       body: Option<arbitrum_alloy_consensus::reth::ArbBlock>|
     -> eyre::Result<bool> {
        if args.max_blocks.is_some_and(|max| blocks >= max) {
            return Ok(false);
        }
        if live_cache.is_none() && args.min_txs > 0 {
            let user_txs = match body.as_ref() {
                Some(body) => body.body.transactions.len().saturating_sub(1),
                None => arbitrum_alloy_sequencer::reader::parse_message(
                    msg.message_with_meta_data.l1_incoming_message.clone(),
                    args.chain_id,
                    0,
                )
                .map(|txs| txs.len())
                .unwrap_or(0),
            };
            if user_txs < args.min_txs {
                skipped.set(skipped.get() + 1);
                return Ok(true);
            }
        }
        let provider = factory.provider()?;
        let (Some(parent), Some(canonical)) = (
            provider.header_by_number(block - 1)?,
            provider.header_by_number(block)?,
        ) else {
            skipped.set(skipped.get() + 1);
            if let Some(cache) = live_cache.as_ref() {
                cache.clear();
            }
            return Ok(true);
        };
        let body = match body {
            Some(body) => Some(body),
            None if args.tx_detail => provider.block_by_number(block)?,
            None => None,
        };
        let receipts = if args.tx_detail {
            provider.receipts_by_block(block.into())?
        } else {
            None
        };
        drop(provider);
        let parent = SealedHeader::seal_slow(parent);
        let canonical = SealedHeader::seal_slow(canonical);

        if args.early
            && let Some(broadcaster) = broadcaster.as_ref()
        {
            let started = Instant::now();
            if broadcaster.publish_early_feed_txs(&msg, args.chain_id, block, started) {
                early_published += 1;
                early_us.push(us(started.elapsed()));
            }
        }
        let per_block_cache =
            (live_cache.is_none() && args.cache_mb > 0).then(|| ArbReexecCache::new(args.cache_mb << 20));
        let cache = live_cache.as_ref().or(per_block_cache.as_ref());
        let mut last = None;
        let mut miss = None;
        for _ in 0..repeat {
            recorder.clear();
            let exec: Box<dyn StateProvider> = factory.history_by_block_number(block - 1)?;
            let trie: Box<dyn StateProvider> = factory.history_by_block_number(block - 1)?;
            let stats = live_cache.is_some().then(|| Arc::new(ArbMissStats::default()));
            let prewarm = (args.prewarm_threads > 0 && live_cache.is_some())
                .then_some(body.as_ref())
                .flatten();
            let started = Instant::now();
            let result = std::thread::scope(|scope| {
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                if let Some(body) = prewarm {
                    let user = body.body.transactions.len().saturating_sub(1);
                    let threads = args.prewarm_threads.min(user.max(1));
                    for worker in 0..threads {
                        // Each worker executes its strided slice one small chunk at a time, so it
                        // can stop as soon as the serial execution has finished.
                        let positions: Vec<usize> = (worker..user).step_by(threads).collect();
                        let stop = Arc::clone(&stop);
                        let factory = &factory;
                        let evm_config = &evm_config;
                        let parent = &parent;
                        let live_cache = live_cache.as_ref();
                        let chain_id = args.chain_id;
                        let genesis_block = args.genesis_block;
                        scope.spawn(move || {
                            for chunk in positions.chunks(4) {
                                if stop.load(std::sync::atomic::Ordering::Relaxed) {
                                    break;
                                }
                                let Some(mini) =
                                    synth_message_subset(body, block, genesis_block, Some(chunk))
                                else {
                                    break;
                                };
                                let (Ok(exec), Ok(trie)) = (
                                    factory.history_by_block_number(block - 1),
                                    factory.history_by_block_number(block - 1),
                                ) else {
                                    break;
                                };
                                let _ = reexecute_message_ext(
                                    evm_config,
                                    chain_id,
                                    parent,
                                    &mini,
                                    exec,
                                    trie,
                                    None,
                                    live_cache,
                                    true,
                                    ArbReexecOptions::default(),
                                );
                            }
                        });
                    }
                }
                let result = reexecute_message_ext(
                    &evm_config,
                    args.chain_id,
                    &parent,
                    &msg,
                    exec,
                    trie,
                    broadcaster.as_ref(),
                    cache,
                    !args.verify_state_root,
                    ArbReexecOptions {
                        miss_stats: stats.clone(),
                        want_bundle: live_cache.is_some(),
                    },
                );
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                result
            })?;
            let wall = started.elapsed();
            let matches = if args.verify_state_root {
                result.block_hash == canonical.hash()
            } else {
                result.receipts_root == canonical.receipts_root
                    && result.transactions_root == canonical.transactions_root
                    && result.logs_bloom == canonical.logs_bloom
                    && result.gas_used == canonical.gas_used
            };
            if !matches {
                mismatches += 1;
                eprintln!(
                    "MISMATCH block {block}: produced {} (state {} receipts {} gas {}) canonical {} (state {} receipts {} gas {})",
                    result.block_hash,
                    result.state_root,
                    result.receipts_root,
                    result.gas_used,
                    canonical.hash(),
                    canonical.state_root,
                    canonical.receipts_root,
                    canonical.gas_used,
                );
            }
            if let Some(cache) = live_cache.as_ref() {
                match (matches, result.bundle.as_ref()) {
                    (true, Some(bundle)) => {
                        if !cache.apply_block(bundle) {
                            eprintln!("live cache: inconsistent bundle at {block}; cleared");
                        }
                    }
                    _ => cache.clear(),
                }
            }
            miss = stats;
            last = Some((result, wall, matches));
        }
        let (result, _wall, matches) = last.expect("at least one run");
        let tx_samples: Vec<f64> = recorder
            .take("arb_reth.mev.tx_exec_seconds")
            .into_iter()
            .map(|seconds| seconds * 1e6)
            .collect();
        if args.early && broadcaster.is_some() {
            // Let the consumer thread catch up with this block's frames.
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let done = manifests.lock().is_ok_and(|m| {
                    m.contains_key(&(block, false)) && m.contains_key(&(block, true))
                });
                if done || Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_micros(200));
            }
            if let Ok(mut m) = manifests.lock() {
                let late = m.remove(&(block, false));
                let early = m.remove(&(block, true));
                if early.is_some() && early != late {
                    early_mismatches += 1;
                    eprintln!("EARLY MANIFEST MISMATCH block {block}");
                }
            }
        }
        // Cache-miss accounting (live-like mode) and the same slots re-read through `latest`.
        let mut miss_extra = serde_json::Map::new();
        let (miss_counts, miss_us, retime_us, retime_n) = match miss.as_ref() {
            Some(stats) => {
                let ordering = std::sync::atomic::Ordering::Relaxed;
                let counts = [
                    stats.accounts.load(ordering),
                    stats.storage.load(ordering),
                    stats.code.load(ordering),
                ];
                let miss_us = stats.nanos.load(ordering) as f64 / 1e3;
                miss_extra.insert("miss_slow".into(), stats.slow.load(ordering).into());
                miss_extra.insert(
                    "miss_max_us".into(),
                    (stats.max_nanos.load(ordering) as f64 / 1e3).into(),
                );
                let (retime_us, retime_n) = if args.retime_misses {
                    let keys = stats.keys.lock().map(|k| k.clone()).unwrap_or_default();
                    let latest = factory.latest()?;
                    let mut each = Vec::with_capacity(keys.len());
                    let started = Instant::now();
                    for (address, key) in &keys {
                        let one = Instant::now();
                        let _ = latest.storage(*address, *key);
                        each.push(one.elapsed().as_nanos() as f64 / 1e3);
                    }
                    let total = us(started.elapsed());
                    each.sort_by(|a, b| a.total_cmp(b));
                    miss_extra.insert("retime_p50_us".into(), percentile(&each, 50.0).into());
                    miss_extra.insert(
                        "retime_max_us".into(),
                        each.last().copied().unwrap_or(0.0).into(),
                    );
                    miss_extra.insert(
                        "retime_slow".into(),
                        each.iter().filter(|v| **v > 100.0).count().into(),
                    );
                    (total, keys.len())
                } else {
                    (0.0, 0)
                };
                (Some(counts), miss_us, retime_us, retime_n)
            }
            None => (None, 0.0, 0.0, 0),
        };
        let tx_detail: Option<Vec<serde_json::Value>> = if args.tx_detail {
            body.as_ref().map(|body| {
                use alloy_consensus::Transaction as _;
                let mut previous_cumulative = 0u64;
                let gas: Vec<u64> = receipts
                    .as_ref()
                    .map(|receipts| {
                        receipts
                            .iter()
                            .map(|receipt| {
                                let cumulative = receipt.cumulative_gas_used();
                                let used = cumulative.saturating_sub(previous_cumulative);
                                previous_cumulative = cumulative;
                                used
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                body.body
                    .transactions
                    .iter()
                    .enumerate()
                    .skip(1)
                    .zip(tx_samples.iter())
                    .map(|((index, tx), sample)| {
                        let to = tx
                            .to()
                            .map(|to| format!("{to:#x}"))
                            .unwrap_or_else(|| "create".to_string());
                        let input = tx.input();
                        let selector = if input.len() >= 4 {
                            format!("0x{}", alloy_primitives::hex::encode(&input[..4]))
                        } else {
                            String::new()
                        };
                        serde_json::json!([
                            to,
                            selector,
                            gas.get(index).copied().unwrap_or(0),
                            (sample * 10.0).round() / 10.0,
                            tx.ty(),
                            input.len()
                        ])
                    })
                    .collect()
            })
        } else {
            None
        };
        let user_txs = result.transactions.saturating_sub(1).max(1);
        blocks += 1;
        tail_us.push(us(result.tail_frame));
        feed_txs_us.push(us(result.feed_txs_frame));
        derived_us.push(us(result.derived_transactions));
        per_tx_mean_us.push(us(result.derived_transactions) / user_txs as f64);
        total_us.push(us(result.total));
        tx_exec_us.extend_from_slice(&tx_samples);
        if let Some(out) = out.as_mut() {
            let mut line = serde_json::json!({
                "block": block,
                "txs": result.transactions,
                "gas": result.gas_used,
                "ok": matches,
                "full_hash_checked": args.verify_state_root,
                "total_us": us(result.total),
                "execution_us": us(result.execution),
                "setup_us": us(result.execution_setup),
                "derived_us": us(result.derived_transactions),
                "feed_txs_us": us(result.feed_txs_frame),
                "tail_us": us(result.tail_frame),
                "finish_us": us(result.finish),
                "tx_exec_us": tx_samples,
            });
            if let Some(counts) = miss_counts {
                line["miss"] = serde_json::json!(counts);
                line["miss_us"] = serde_json::json!(miss_us);
                line["retime_us"] = serde_json::json!(retime_us);
                line["retime_n"] = serde_json::json!(retime_n);
                for (key, value) in miss_extra {
                    line[key] = value;
                }
            }
            if let Some(detail) = tx_detail {
                line["tx"] = serde_json::Value::Array(detail);
            }
            writeln!(out, "{line}")?;
        }
        if blocks.is_multiple_of(500) {
            eprintln!("replay-bench: {blocks} blocks, {mismatches} mismatches");
        }
        Ok(true)
    };

    if args.synth_from_db {
        let (Some(from), Some(to)) = (args.from, args.to) else {
            eyre::bail!("--synth-from-db needs --from and --to");
        };
        for block in from.max(1)..=to.min(last_block) {
            let body = factory.provider()?.block_by_number(block)?;
            let msg = body
                .as_ref()
                .and_then(|body| synth_message(body, block, args.genesis_block));
            match msg {
                Some(msg) => {
                    if !process(block, msg, body)? {
                        break;
                    }
                }
                None => {
                    skipped.set(skipped.get() + 1);
                    if let Some(cache) = live_cache.as_ref() {
                        cache.clear();
                    }
                }
            }
        }
    } else {
        let feed = args
            .feed
            .as_ref()
            .ok_or_else(|| eyre::eyre!("--feed is required without --synth-from-db"))?;
        let reader = BufReader::new(fs::File::open(feed)?);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let msg: BroadcastFeedMessage = serde_json::from_str(line)?;
            let block = msg.sequence_number + args.genesis_block;
            if args.from.is_some_and(|from| block < from)
                || args.to.is_some_and(|to| block > to)
                || block == 0
                || block > last_block
            {
                skipped.set(skipped.get() + 1);
                continue;
            }
            if !process(block, msg, None)? {
                break;
            }
        }
    }
    drop(process);
    if let Some(out) = out.as_mut() {
        out.flush()?;
    }

    println!(
        "replay-bench: blocks={blocks} mismatches={mismatches} skipped={} stream={} frontiers={} full_hash={} live_cache={} events_drained={}",
        skipped.get(),
        !args.no_stream,
        !args.no_frontiers,
        args.verify_state_root,
        args.live_cache_mb,
        drained.load(std::sync::atomic::Ordering::Relaxed)
    );
    println!("(microseconds; per-block values are from the last of {repeat} runs)");
    summarize("tail_frame_us (block)", tail_us);
    summarize("feed_txs_frame_us (block)", feed_txs_us);
    summarize("derived_txs_us (block)", derived_us);
    summarize("per_tx_mean_us (block)", per_tx_mean_us);
    summarize("tx_exec_us (tx)", tx_exec_us);
    summarize("total_us (block)", total_us);
    if args.early {
        println!("early manifests published={early_published} mismatches_vs_late={early_mismatches}");
        summarize("early_publish_us (block)", early_us);
    }
    if early_mismatches != 0 {
        eyre::bail!("{early_mismatches} early manifests differ from the late manifest");
    }
    if mismatches != 0 {
        eyre::bail!("{mismatches} produced blocks differ from canonical");
    }
    Ok(())
}
