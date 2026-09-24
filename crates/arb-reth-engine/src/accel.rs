//! Big-block acceleration (both opt-in; off = the previous single-threaded behavior).
//!
//! - [`ArbTxPrecompute`]: when the first copy of a sequencer message arrives, decode it and, on a
//!   small dedicated pool, compute per transaction everything that does not depend on execution
//!   order: sender recovery, canonical EIP-2718 bytes (and the hash, cached while decoding), and
//!   the brotli-compressed length ArbOS needs for the L1 poster cost. The payload builder later
//!   takes the result for the same message and skips that work on its (serial) thread. A result
//!   that is missing, not finished, or not provably for the same message is simply not used.
//! - [`ArbPrewarm`]: while the builder executes a block, a few workers execute the same
//!   transactions on the *parent* state through the shared execution cache (fill on miss), results
//!   discarded, so the builder's own reads hit the cache instead of the database. Workers are
//!   stopped and joined (and have dropped every cache handle) before the builder returns, i.e.
//!   before the engine tree advances the shared cache with the block's changes.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use alloy_eips::eip2718::{Encodable2718 as _, Typed2718 as _};
use alloy_evm::FromRecoveredTx as _;
use alloy_primitives::{Address, Bytes};
use alloy_consensus::Header;
use arb_reth_evm::{ArbEvmConfig, ArbTx, config::ArbNextBlockEnvAttributes};
use arb_revm::{ArbosState, L1CompressedLen, set_thread_handler_metrics};
use arbitrum_alloy_consensus::ArbTxEnvelope;
use arbitrum_alloy_sequencer::sequencer::feed::{BroadcastFeedMessage, L1IncomingMessage};
use metrics::{Counter, Histogram};
use reth_evm::{ConfigureEvm as _, Evm as _};
use reth_execution_cache::{CachedStateProvider, ExecutionCache};
use reth_primitives_traits::SealedHeader;
use reth_revm::State;
use reth_revm::database::StateProviderDatabase;
use reth_provider::{ProviderResult, StateProvider, StateProviderBox};
use revm::context_interface::ContextTr as _;

use crate::engine::ArbMissStats;

/// Nitro `L1MessageType_BatchPostingReport`: its decoding depends on the ArbOS version, which the
/// feed side does not know. Never precomputed.
const L1_MESSAGE_BATCH_POSTING_REPORT: u8 = 13;

/// Sequencer-message results kept for the builder. The builder takes each one at most once;
/// old entries (L1-derived catch-up, a driver far behind) simply age out.
const PRECOMPUTE_CAPACITY: usize = 64;

/// Brotli level not yet observed (no block executed since start).
const LEVEL_UNKNOWN: u32 = u32::MAX;

/// Transaction types that carry no L1 poster cost (Nitro `TxTypeHasPosterCosts`).
const fn has_poster_costs(tx_type: u8) -> bool {
    !matches!(tx_type, 0x64 | 0x68 | 0x69 | 0x6a)
}

/// Pins the calling thread to `cpus` (Linux; no-op elsewhere or for an empty list).
pub fn pin_current_thread(cpus: &[usize]) {
    #[cfg(target_os = "linux")]
    {
        if cpus.is_empty() {
            return;
        }
        // SAFETY: `cpu_set_t` is plain data; CPU_ZERO/CPU_SET only write inside it and
        // `sched_setaffinity(0, ..)` affects only the calling thread.
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            for &cpu in cpus {
                if cpu < libc::CPU_SETSIZE as usize {
                    libc::CPU_SET(cpu, &mut set);
                }
            }
            let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cpus;
}

/// Parses a CPU list such as `0-14,16-30`.
pub fn parse_cpu_list(raw: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|part| !part.is_empty()) {
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: usize = lo.trim().parse().map_err(|_| format!("bad cpu `{part}`"))?;
                let hi: usize = hi.trim().parse().map_err(|_| format!("bad cpu `{part}`"))?;
                if lo > hi {
                    return Err(format!("bad cpu range `{part}`"));
                }
                cpus.extend(lo..=hi);
            }
            None => cpus.push(part.parse().map_err(|_| format!("bad cpu `{part}`"))?),
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Ok(cpus)
}

fn build_pool(
    threads: usize,
    name: &'static str,
    cpus: Vec<usize>,
    handler_metrics: bool,
) -> Arc<rayon::ThreadPool> {
    let cpus = Arc::new(cpus);
    Arc::new(
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads.max(1))
            .thread_name(move |index| format!("{name}-{index}"))
            .start_handler(move |_| {
                pin_current_thread(&cpus);
                if !handler_metrics {
                    set_thread_handler_metrics(false);
                }
            })
            // A panic in best-effort work must not abort the node (rayon's default). The job's
            // guards still run: a prewarm worker still signals completion.
            .panic_handler(move |_| {
                tracing::warn!(target: "arb-reth::engine", pool = name, "accel worker panicked; result discarded");
            })
            .build()
            .expect("build accel thread pool"),
    )
}

/// Big-block acceleration handed to the payload builder. `Default` = both off (the previous
/// behavior, bit for bit).
#[derive(Clone, Debug, Default)]
pub struct ArbBuildAccel {
    /// #3: feed-arrival precompute; the feed coordinator must also be given the same instance.
    pub precompute: Option<ArbTxPrecompute>,
    /// #4: execution-cache prewarm (only runs when the builder has a shared execution cache).
    pub prewarm: Option<ArbPrewarm>,
}

// ---------------------------------------------------------------------------------------------
// #3: feed-arrival precompute
// ---------------------------------------------------------------------------------------------

/// Per-transaction work done off the builder thread.
#[derive(Clone, Debug)]
pub(crate) struct PreTx {
    /// Recovered sender; `None` if recovery failed (the builder then recovers inline to report
    /// the same error it always did).
    pub(crate) sender: Option<Address>,
    pub(crate) encoded: Bytes,
    pub(crate) l1: Option<L1CompressedLen>,
}

/// One decoded sequencer message and its per-transaction slots (filled concurrently).
#[derive(Debug)]
pub struct PrecomputedBlock {
    sequence_number: u64,
    l1_message: L1IncomingMessage,
    pub(crate) txs: Vec<ArbTxEnvelope>,
    slots: Vec<OnceLock<PreTx>>,
    submitted_at: Instant,
    remaining: AtomicUsize,
}

impl PrecomputedBlock {
    /// The slot for user transaction `index`, if it has been computed already.
    pub(crate) fn ready(&self, index: usize) -> Option<&PreTx> {
        self.slots.get(index).and_then(OnceLock::get)
    }

    /// Number of decoded user transactions.
    pub(crate) fn len(&self) -> usize {
        self.txs.len()
    }

    /// Time since the message was submitted.
    pub(crate) fn age(&self) -> Duration {
        self.submitted_at.elapsed()
    }
}

struct PrecomputeMetrics {
    parse: Histogram,
    ready: Histogram,
    lead: Histogram,
    block_hit: Counter,
    block_absent: Counter,
    block_mismatch: Counter,
    tx_ready: Counter,
    tx_late: Counter,
}

fn precompute_metrics() -> &'static PrecomputeMetrics {
    static HANDLES: OnceLock<PrecomputeMetrics> = OnceLock::new();
    HANDLES.get_or_init(|| PrecomputeMetrics {
        parse: metrics::histogram!("arb_reth.precompute.parse_seconds"),
        ready: metrics::histogram!("arb_reth.precompute.ready_seconds"),
        lead: metrics::histogram!("arb_reth.precompute.lead_seconds"),
        block_hit: metrics::counter!("arb_reth.precompute.blocks_total", "result" => "hit"),
        block_absent: metrics::counter!("arb_reth.precompute.blocks_total", "result" => "absent"),
        block_mismatch: metrics::counter!(
            "arb_reth.precompute.blocks_total",
            "result" => "mismatch"
        ),
        tx_ready: metrics::counter!("arb_reth.precompute.txs_total", "result" => "ready"),
        tx_late: metrics::counter!("arb_reth.precompute.txs_total", "result" => "late"),
    })
}

struct PrecomputeInner {
    pool: Arc<rayon::ThreadPool>,
    chain_id: u64,
    brotli_level: AtomicU32,
    blocks: Mutex<VecDeque<(u64, Arc<PrecomputedBlock>)>>,
}

/// Feed-arrival transaction precompute shared by the feed coordinator (producer) and the payload
/// builder (consumer). Cheap to clone.
#[derive(Clone)]
pub struct ArbTxPrecompute {
    inner: Arc<PrecomputeInner>,
}

impl core::fmt::Debug for ArbTxPrecompute {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArbTxPrecompute")
            .field("chain_id", &self.inner.chain_id)
            .field("threads", &self.inner.pool.current_num_threads())
            .finish()
    }
}

impl ArbTxPrecompute {
    /// Creates the precompute with a dedicated pool of `threads` workers (named
    /// `arb-precomp-N`), optionally pinned to `cpus`. Create it at startup so later `taskset -a`
    /// calls cover its threads.
    pub fn new(chain_id: u64, threads: usize, cpus: Vec<usize>) -> Self {
        Self {
            inner: Arc::new(PrecomputeInner {
                pool: build_pool(threads, "arb-precomp", cpus, true),
                chain_id,
                brotli_level: AtomicU32::new(LEVEL_UNKNOWN),
                blocks: Mutex::new(VecDeque::with_capacity(PRECOMPUTE_CAPACITY)),
            }),
        }
    }

    /// Records the ArbOS brotli level the builder last observed. Precomputed lengths carry the
    /// level they were computed at; ArbOS ignores a length computed at a different level.
    pub fn set_brotli_level(&self, level: u32) {
        self.inner.brotli_level.store(level, Ordering::Relaxed);
    }

    /// The brotli level used for new precomputations (`None` until a block has executed).
    pub fn brotli_level(&self) -> Option<u32> {
        let level = self.inner.brotli_level.load(Ordering::Relaxed);
        (level != LEVEL_UNKNOWN).then_some(level)
    }

    /// Starts precomputing `msg` (an owned copy) in the background. Never blocks the caller.
    pub fn submit(&self, msg: BroadcastFeedMessage) {
        let l1_message = msg.message_with_meta_data.l1_incoming_message;
        if l1_message.header.kind == L1_MESSAGE_BATCH_POSTING_REPORT {
            return;
        }
        let submitted_at = Instant::now();
        let sequence_number = msg.sequence_number;
        let inner = Arc::clone(&self.inner);
        self.inner.pool.spawn(move || {
            let metrics = precompute_metrics();
            let parse_started_at = Instant::now();
            // Same decoder and arguments as block production (`digest_message`); the version
            // only matters for batch-posting reports, excluded above.
            let Ok(txs) = arbitrum_alloy_sequencer::reader::parse_message(
                l1_message.clone(),
                inner.chain_id,
                0,
            ) else {
                return;
            };
            metrics.parse.record(parse_started_at.elapsed().as_secs_f64());
            let slots = (0..txs.len()).map(|_| OnceLock::new()).collect();
            let block = Arc::new(PrecomputedBlock {
                sequence_number,
                l1_message,
                remaining: AtomicUsize::new(txs.len()),
                txs,
                slots,
                submitted_at,
            });
            {
                let mut blocks = inner
                    .blocks
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                blocks.retain(|(seq, _)| *seq != sequence_number);
                if blocks.len() >= PRECOMPUTE_CAPACITY {
                    blocks.pop_front();
                }
                blocks.push_back((sequence_number, Arc::clone(&block)));
            }
            if block.txs.is_empty() {
                metrics.ready.record(submitted_at.elapsed().as_secs_f64());
                return;
            }
            let level = inner.brotli_level.load(Ordering::Relaxed);
            // Fill the slots in execution order (the builder needs the first ones first): every
            // pool thread takes the next index from a shared counter. This thread participates.
            let next = AtomicUsize::new(0);
            let work = || {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(tx) = block.txs.get(index) else {
                        break;
                    };
                    let _ = block.slots[index].set(precompute_tx(tx, level));
                    if block.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                        metrics.ready.record(block.submitted_at.elapsed().as_secs_f64());
                    }
                }
            };
            let helpers = inner
                .pool
                .current_num_threads()
                .saturating_sub(1)
                .min(block.txs.len().saturating_sub(1));
            rayon::scope(|scope| {
                for _ in 0..helpers {
                    scope.spawn(|_| work());
                }
                work();
            });
        });
    }

    /// Waits (polling) until the result for `sequence_number` is fully computed, up to `timeout`.
    /// Returns whether it is. For replay and tests; the live node never waits.
    pub fn wait_ready(&self, sequence_number: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let ready = self
                .inner
                .blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|(seq, block)| {
                    *seq == sequence_number && block.remaining.load(Ordering::Acquire) == 0
                });
            if ready {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_micros(20));
        }
    }

    /// Takes the precomputed result for `msg` if it exists and was provably computed from the
    /// same message (identical L1 message, same chain id). Partially filled results are returned
    /// too; the caller falls back per transaction.
    pub(crate) fn take(
        &self,
        msg: &BroadcastFeedMessage,
        chain_id: u64,
    ) -> Option<Arc<PrecomputedBlock>> {
        let metrics = precompute_metrics();
        let block = {
            let mut blocks = self
                .inner
                .blocks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let position = blocks
                .iter()
                .position(|(seq, _)| *seq == msg.sequence_number);
            position.and_then(|position| blocks.remove(position)).map(|(_, block)| block)
        };
        let Some(block) = block else {
            metrics.block_absent.increment(1);
            return None;
        };
        if chain_id != self.inner.chain_id
            || block.sequence_number != msg.sequence_number
            || block.l1_message != msg.message_with_meta_data.l1_incoming_message
        {
            metrics.block_mismatch.increment(1);
            return None;
        }
        metrics.block_hit.increment(1);
        metrics.lead.record(block.age().as_secs_f64());
        Some(block)
    }

    /// Records how many of a taken block's transactions were ready when the builder needed them.
    pub(crate) fn record_use(ready: usize, late: usize) {
        let metrics = precompute_metrics();
        metrics.tx_ready.increment(ready as u64);
        metrics.tx_late.increment(late as u64);
    }
}

/// Sender, canonical bytes (hash cached while decoding / here for legacy), brotli length.
fn precompute_tx(tx: &ArbTxEnvelope, level: u32) -> PreTx {
    let sender = tx.sender().ok();
    // Legacy transactions hash lazily; typed ones were hashed while decoding.
    let _ = tx.hash();
    let encoded = Bytes::from(tx.encoded_2718());
    let l1 = (level != LEVEL_UNKNOWN && has_poster_costs(tx.ty()))
        .then(|| L1CompressedLen::compute(&encoded, level));
    PreTx {
        sender,
        encoded,
        l1,
    }
}

// ---------------------------------------------------------------------------------------------
// #4: execution-cache prewarm
// ---------------------------------------------------------------------------------------------

/// Opens a fresh state provider for the parent of the block being built.
pub type ArbStateSource = Arc<dyn Fn() -> ProviderResult<StateProviderBox> + Send + Sync>;

/// What a prewarm run needs from the caller: a way to open parent-state providers and the shared
/// execution cache the builder reads through.
#[derive(Clone)]
pub struct ArbPrewarmInput {
    /// Opens a provider for the parent state (one per worker).
    pub source: ArbStateSource,
    /// The shared cross-block execution cache for the parent.
    pub cache: ExecutionCache,
}

impl core::fmt::Debug for ArbPrewarmInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArbPrewarmInput").finish_non_exhaustive()
    }
}

struct PrewarmMetrics {
    join_wait: Histogram,
    fills: Histogram,
    executed: Counter,
    skipped: Counter,
}

fn prewarm_metrics() -> &'static PrewarmMetrics {
    static HANDLES: OnceLock<PrewarmMetrics> = OnceLock::new();
    HANDLES.get_or_init(|| PrewarmMetrics {
        join_wait: metrics::histogram!("arb_reth.prewarm.join_wait_seconds"),
        fills: metrics::histogram!("arb_reth.prewarm.provider_reads_per_block"),
        executed: metrics::counter!("arb_reth.prewarm.txs_total", "result" => "executed"),
        skipped: metrics::counter!("arb_reth.prewarm.txs_total", "result" => "skipped"),
    })
}

/// Execution-cache prewarm workers. Cheap to clone.
#[derive(Clone)]
pub struct ArbPrewarm {
    pool: Arc<rayon::ThreadPool>,
    threads: usize,
    min_txs: usize,
}

impl core::fmt::Debug for ArbPrewarm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ArbPrewarm")
            .field("threads", &self.threads)
            .field("min_txs", &self.min_txs)
            .finish()
    }
}

/// Outcome of one prewarm run, for replay reporting and metrics.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArbPrewarmStats {
    /// Transactions a worker executed.
    pub executed: u64,
    /// Transactions skipped because the builder had already reached them.
    pub skipped: u64,
    /// Parent-state reads the workers made (cache fills).
    pub provider_reads: u64,
    /// Time the builder waited for the workers after its last transaction.
    pub join_wait: Duration,
}

struct PrewarmShared {
    stop: AtomicBool,
    next: AtomicUsize,
    main_index: AtomicUsize,
    executed: AtomicU64,
    skipped: AtomicU64,
    reads: Arc<ArbMissStats>,
    done: Mutex<usize>,
    done_cv: Condvar,
}

/// A running prewarm. [`PrewarmRun::finish`] must be called (it is also called on drop) before the
/// shared execution cache may be advanced.
pub(crate) struct PrewarmRun {
    shared: Arc<PrewarmShared>,
    workers: usize,
    finished: Option<ArbPrewarmStats>,
}

impl PrewarmRun {
    /// Workers skip user transactions below `index` (the builder has reached them).
    #[inline]
    pub(crate) fn main_at(&self, index: usize) {
        self.shared.main_index.store(index, Ordering::Relaxed);
    }

    /// Tells workers to stop starting new transactions. Non-blocking.
    pub(crate) fn stop(&self) {
        self.shared.stop.store(true, Ordering::Relaxed);
    }

    /// Stops the workers and waits until every one has exited and released its cache handle.
    pub(crate) fn finish(&mut self) -> ArbPrewarmStats {
        if let Some(stats) = self.finished {
            return stats;
        }
        self.stop();
        let wait_started_at = Instant::now();
        let mut done = self
            .shared
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *done < self.workers {
            done = self
                .shared
                .done_cv
                .wait(done)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(done);
        let join_wait = wait_started_at.elapsed();
        let ordering = Ordering::Relaxed;
        let reads = &self.shared.reads;
        let stats = ArbPrewarmStats {
            executed: self.shared.executed.load(ordering),
            skipped: self.shared.skipped.load(ordering),
            provider_reads: reads.accounts.load(ordering)
                + reads.storage.load(ordering)
                + reads.code.load(ordering),
            join_wait,
        };
        let metrics = prewarm_metrics();
        metrics.join_wait.record(join_wait.as_secs_f64());
        metrics.fills.record(stats.provider_reads as f64);
        metrics.executed.increment(stats.executed);
        metrics.skipped.increment(stats.skipped);
        self.finished = Some(stats);
        stats
    }
}

impl Drop for PrewarmRun {
    fn drop(&mut self) {
        // Error paths: never leave workers holding the shared cache.
        let _ = self.finish();
    }
}

/// Signals one finished worker when dropped (also when the worker panics).
struct WorkerDone(Arc<PrewarmShared>);

impl Drop for WorkerDone {
    fn drop(&mut self) {
        let mut done = self
            .0
            .done
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *done += 1;
        self.0.done_cv.notify_all();
    }
}

impl ArbPrewarm {
    /// Creates `threads` prewarm workers (named `arb-prewarm-N`, handler metrics off), optionally
    /// pinned to `cpus`. Blocks with fewer than `min_txs` user transactions are not prewarmed.
    pub fn new(threads: usize, min_txs: usize, cpus: Vec<usize>) -> Self {
        Self {
            pool: build_pool(threads, "arb-prewarm", cpus, false),
            threads: threads.max(1),
            min_txs: min_txs.max(1),
        }
    }

    /// Starts prewarming `txs` for the block `parent + 1` (built with `attrs`). Returns `None`
    /// when the block is too small.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        &self,
        evm_config: &ArbEvmConfig,
        parent: &SealedHeader<Header>,
        attrs: &ArbNextBlockEnvAttributes,
        txs: Arc<Vec<ArbTxEnvelope>>,
        precomputed: Option<Arc<PrecomputedBlock>>,
        input: &ArbPrewarmInput,
    ) -> Option<PrewarmRun> {
        if txs.len() < self.min_txs {
            return None;
        }
        let workers = self.threads.min(txs.len());
        let shared = Arc::new(PrewarmShared {
            stop: AtomicBool::new(false),
            next: AtomicUsize::new(0),
            main_index: AtomicUsize::new(0),
            executed: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            reads: Arc::new(ArbMissStats::default()),
            done: Mutex::new(0),
            done_cv: Condvar::new(),
        });
        let mut evm_env = evm_config.next_evm_env(parent.header(), attrs);
        // As reth's prewarm: execute every tx on the parent state even if an earlier tx of the
        // block would have changed the sender's nonce or funded it.
        evm_env.cfg_env.disable_nonce_check = true;
        evm_env.cfg_env.disable_balance_check = true;
        for _ in 0..workers {
            let shared = Arc::clone(&shared);
            let txs = Arc::clone(&txs);
            let precomputed = precomputed.clone();
            let input = input.clone();
            let evm_config = evm_config.clone();
            let evm_env = evm_env.clone();
            self.pool.spawn(move || {
                let _done = WorkerDone(Arc::clone(&shared));
                if shared.stop.load(Ordering::Relaxed) {
                    return;
                }
                prewarm_worker(&shared, &txs, precomputed.as_deref(), &input, &evm_config, evm_env);
                // Everything holding the cache (provider, state, EVM) was dropped inside
                // `prewarm_worker`; `_done` signals completion only after that.
            });
        }
        Some(PrewarmRun {
            shared,
            workers,
            finished: None,
        })
    }
}

fn prewarm_worker(
    shared: &PrewarmShared,
    txs: &[ArbTxEnvelope],
    precomputed: Option<&PrecomputedBlock>,
    input: &ArbPrewarmInput,
    evm_config: &ArbEvmConfig,
    evm_env: alloy_evm::EvmEnv<arb_revm::ArbSpecId, arb_reth_evm::ArbBlockEnv>,
) {
    let Ok(provider) = (input.source)() else {
        return;
    };
    // Count the reads that reach the database (each one fills the shared cache).
    let provider: Box<dyn StateProvider> = Box::new(crate::engine::MissTimingStateProvider::new(
        provider,
        Arc::clone(&shared.reads),
    ));
    let provider = CachedStateProvider::new_prewarm(provider, input.cache.clone());
    let mut state = State::builder()
        .with_database(StateProviderDatabase::new(provider))
        .build();
    let mut evm = evm_config.evm_with_env(&mut state, evm_env);
    // Same block base fee as the builder (the ArbOS value in the parent state).
    if let Ok(base_fee) = ArbosState::open()
        .l2_pricing
        .base_fee_wei
        .get(evm.ctx_mut().journal_mut())
    {
        let base_fee = u64::try_from(base_fee).unwrap_or(u64::MAX);
        evm.ctx_mut().modify_block(|block| {
            block.inner.basefee = base_fee;
            block.base_fee_in_block = base_fee;
        });
        evm.ctx_mut().chain.base_fee_in_block = Some(base_fee);
    }
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        let index = shared.next.fetch_add(1, Ordering::Relaxed);
        let Some(tx) = txs.get(index) else {
            break;
        };
        if index < shared.main_index.load(Ordering::Relaxed) {
            shared.skipped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let pre = precomputed
            .filter(|block| block.len() == txs.len())
            .and_then(|block| block.ready(index));
        let sender = match pre.and_then(|pre| pre.sender) {
            Some(sender) => sender,
            None => match tx.sender() {
                Ok(sender) => sender,
                Err(_) => continue,
            },
        };
        let env = match pre {
            Some(pre) => ArbTx::from_precomputed(tx, sender, pre.encoded.clone(), pre.l1),
            None => ArbTx::from_recovered_tx(tx, sender),
        };
        let _ = evm.transact(env);
        shared.executed.fetch_add(1, Ordering::Relaxed);
    }
}
