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

use std::{
    collections::HashMap,
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::ArbNode;
use arb_reth_engine::{ArbTxLogBroadcaster, reexecute_message};
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
use reth_provider::{BlockNumReader, HeaderProvider, StateProvider, StorageSettingsCache};

/// Re-execute recorded feed messages against a datadir and time block production.
#[derive(Debug, Parser)]
#[command(name = "replay-bench", about = "Re-execute recorded feed messages and time production")]
pub struct ReplayBenchArgs {
    /// Node datadir (opened read-only; the node may keep running).
    #[arg(long, value_name = "PATH")]
    datadir: PathBuf,

    /// NDJSON file with one `BroadcastFeedMessage` per line (the feed's `messages[]` items).
    #[arg(long, value_name = "PATH")]
    feed: PathBuf,

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

    /// Compute the state root and compare full block hashes (slow). Default compares receipts
    /// root, transactions root, logs bloom and gas used.
    #[arg(long)]
    verify_state_root: bool,

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
    let broadcaster = (!args.no_stream).then(ArbTxLogBroadcaster::new);
    let drained = Arc::new(std::sync::atomic::AtomicU64::new(0));
    if let Some(broadcaster) = broadcaster.as_ref() {
        let mut receiver = broadcaster.subscribe();
        let drained = Arc::clone(&drained);
        std::thread::spawn(move || {
            loop {
                match receiver.blocking_recv() {
                    Ok(_) => {
                        drained.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    let reader = BufReader::new(fs::File::open(&args.feed)?);
    let mut blocks = 0usize;
    let mut mismatches = 0usize;
    let mut skipped = 0usize;
    let mut tail_us = Vec::new();
    let mut feed_txs_us = Vec::new();
    let mut derived_us = Vec::new();
    let mut per_tx_mean_us = Vec::new();
    let mut tx_exec_us = Vec::new();
    let mut total_us = Vec::new();
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
            skipped += 1;
            continue;
        }
        if args.max_blocks.is_some_and(|max| blocks >= max) {
            break;
        }
        let provider = factory.provider()?;
        let (Some(parent), Some(canonical)) = (
            provider.header_by_number(block - 1)?,
            provider.header_by_number(block)?,
        ) else {
            skipped += 1;
            continue;
        };
        drop(provider);
        let parent = SealedHeader::seal_slow(parent);
        let canonical = SealedHeader::seal_slow(canonical);

        let cache = (args.cache_mb > 0)
            .then(|| arb_reth_engine::ArbReexecCache::new(args.cache_mb << 20));
        let mut last = None;
        for _ in 0..args.repeat.max(1) {
            recorder.clear();
            let exec: Box<dyn StateProvider> = factory.history_by_block_number(block - 1)?;
            let trie: Box<dyn StateProvider> = factory.history_by_block_number(block - 1)?;
            let started = Instant::now();
            let result = reexecute_message(
                &evm_config,
                args.chain_id,
                &parent,
                &msg,
                exec,
                trie,
                broadcaster.as_ref(),
                cache.as_ref(),
                !args.verify_state_root,
            )?;
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
            last = Some((result, wall, matches));
        }
        let (result, _wall, matches) = last.expect("at least one run");
        let tx_samples: Vec<f64> = recorder
            .take("arb_reth.mev.tx_exec_seconds")
            .into_iter()
            .map(|seconds| seconds * 1e6)
            .collect();
        let user_txs = result.transactions.saturating_sub(1).max(1);
        blocks += 1;
        tail_us.push(us(result.tail_frame));
        feed_txs_us.push(us(result.feed_txs_frame));
        derived_us.push(us(result.derived_transactions));
        per_tx_mean_us.push(us(result.derived_transactions) / user_txs as f64);
        total_us.push(us(result.total));
        tx_exec_us.extend_from_slice(&tx_samples);
        if let Some(out) = out.as_mut() {
            writeln!(
                out,
                "{}",
                serde_json::json!({
                    "block": block,
                    "txs": result.transactions,
                    "gas": result.gas_used,
                    "ok": matches,
                    "full_hash_checked": args.verify_state_root,
                    "total_us": us(result.total),
                    "execution_us": us(result.execution),
                    "derived_us": us(result.derived_transactions),
                    "feed_txs_us": us(result.feed_txs_frame),
                    "tail_us": us(result.tail_frame),
                    "finish_us": us(result.finish),
                    "tx_exec_us": tx_samples,
                })
            )?;
        }
        if blocks.is_multiple_of(200) {
            eprintln!("replay-bench: {blocks} blocks, {mismatches} mismatches");
        }
    }
    if let Some(out) = out.as_mut() {
        out.flush()?;
    }

    println!(
        "replay-bench: blocks={blocks} mismatches={mismatches} skipped={skipped} stream={} full_hash={} events_drained={}",
        !args.no_stream,
        args.verify_state_root,
        drained.load(std::sync::atomic::Ordering::Relaxed)
    );
    println!("(microseconds; per-block values are from the last of {} runs)", args.repeat.max(1));
    summarize("tail_frame_us (block)", tail_us);
    summarize("feed_txs_frame_us (block)", feed_txs_us);
    summarize("derived_txs_us (block)", derived_us);
    summarize("per_tx_mean_us (block)", per_tx_mean_us);
    summarize("tx_exec_us (tx)", tx_exec_us);
    summarize("total_us (block)", total_us);
    if mismatches != 0 {
        eyre::bail!("{mismatches} produced blocks differ from canonical");
    }
    Ok(())
}
