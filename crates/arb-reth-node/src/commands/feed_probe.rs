//! `arb-reth feed-probe`：只跑节点的 sequencer-feed 客户端（多 lane 抽签 + 去重协调器 + 换票 +
//! 续传），不开数据库、不执行、不写任何节点数据。每个首次到达的序号写一行 TSV：
//!
//! ```text
//! <sequence>\t<到达时刻 unix 纳秒>\t<消息 JSON 字节数>\t<消息内容 keccak 前 8 字节>
//! ```
//!
//! 用途：在不动正式节点的前提下，验证 feed 客户端改动（例如 `--feed-deflate` 直连官方压缩 feed），
//! 并和另一条路径（例如本机 Python 解压中继）同机并跑、逐条比对内容和到达时刻。
//! lane 的连接 / 断线 / 换票日志与节点完全相同（同一份 `feed::follow` / `feed::coordinate`）。

use crate::{feed, metrics::FeedLatencyTracker};
use alloy_primitives::keccak256;
use clap::Args;
use std::{
    io::Write,
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, atomic::AtomicU64},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Args)]
pub struct FeedProbeArgs {
    /// Feed relay（同 `node --feed-url`，可重复）。
    #[arg(long = "feed-url", value_name = "URL", action = clap::ArgAction::Append, required = true)]
    feed_urls: Vec<String>,

    /// 每个 `--feed-url` 的不绑源 IP 连接数（同 `node --feed-connections`）。
    #[arg(long = "feed-connections", value_name = "COUNT")]
    feed_connections: Option<usize>,

    /// 绑源 IP 的连接（同 `node --feed-source IP=COUNT`）。
    #[arg(long = "feed-source", value_name = "IP=COUNT", action = clap::ArgAction::Append)]
    feed_sources: Vec<feed::FeedSourceSpec>,

    /// 换票备用地址（同 `node --feed-spare-ip`）。
    #[arg(long = "feed-spare-ip", value_name = "IP", action = clap::ArgAction::Append)]
    feed_spare_ips: Vec<IpAddr>,

    /// 同 `node --feed-rotate-lag-ms`。
    #[arg(long = "feed-rotate-lag-ms", value_name = "MS", default_value_t = 30)]
    feed_rotate_lag_ms: u64,

    /// 同 `node --feed-rotate-window-secs`。
    #[arg(long = "feed-rotate-window-secs", value_name = "SECS", default_value_t = 600)]
    feed_rotate_window_secs: u64,

    /// 同 `node --feed-deflate`：握手报 permessage-deflate，按服务端应答解压。
    #[arg(long = "feed-deflate")]
    feed_deflate: bool,

    /// 第一次连接请求的序号（`arbitrum-requested-sequence-number`）；之后按收到的连续前缀续传。
    #[arg(long = "from-seq", value_name = "SEQ")]
    from_seq: u64,

    /// TSV 输出文件。
    #[arg(long = "out", value_name = "PATH")]
    out: PathBuf,

    /// 跑多久（秒）；0 = 一直跑到被杀。
    #[arg(long = "duration-secs", value_name = "SECS", default_value_t = 0)]
    duration_secs: u64,
}

pub fn run(args: FeedProbeArgs) -> eyre::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(probe(args))
}

async fn probe(args: FeedProbeArgs) -> eyre::Result<()> {
    let mut sources =
        feed::expand_feed_sources(&args.feed_urls, args.feed_connections, &args.feed_sources)?;
    for source in &mut sources {
        source.set_deflate(args.feed_deflate);
    }
    let resume = Arc::new(AtomicU64::new(args.from_seq));
    let (ingress_tx, ingress_rx) = feed::ingress_channel();
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(4096);

    // 换票接线与 node.rs 相同：绑源 IP 的 lane 各一条命令通道。
    let mut lane_receivers = Vec::with_capacity(sources.len());
    let rotation = (!args.feed_spare_ips.is_empty()).then(|| {
        let mut lanes = Vec::with_capacity(sources.len());
        for source in &sources {
            if source.is_bound() {
                let (tx, rx) = feed::rotation_channel();
                lanes.push(Some(tx));
                lane_receivers.push(Some(rx));
            } else {
                lanes.push(None);
                lane_receivers.push(None);
            }
        }
        feed::Rotation {
            pool: feed::RotationPool::new(args.feed_spare_ips.clone()),
            policy: feed::RotationPolicy {
                lag: Duration::from_millis(args.feed_rotate_lag_ms),
                window: Duration::from_secs(args.feed_rotate_window_secs),
                min_samples: 200,
            },
            lanes,
        }
    });
    let rotation_pool = rotation.as_ref().map(|rotation| rotation.pool.clone());
    tokio::spawn(feed::coordinate(
        ingress_rx,
        output_tx,
        FeedLatencyTracker::new(),
        resume.clone(),
        rotation,
        None,
        None,
    ));
    for (index, source) in sources.into_iter().enumerate() {
        let lane = match (
            rotation_pool.as_ref(),
            lane_receivers.get_mut(index).and_then(Option::take),
        ) {
            (Some(pool), Some(rx)) => Some((pool.clone(), rx)),
            _ => None,
        };
        tokio::spawn(feed::follow(source, ingress_tx.clone(), resume.clone(), lane));
    }
    drop(ingress_tx);

    let mut out = std::io::BufWriter::new(std::fs::File::create(&args.out)?);
    let started = Instant::now();
    let deadline = (args.duration_secs > 0).then(|| started + Duration::from_secs(args.duration_secs));
    let mut report_at = started + Duration::from_secs(30);
    let (mut count, mut max_seq, mut out_of_order) = (0u64, 0u64, 0u64);
    loop {
        let wait = deadline.map_or(Duration::from_secs(1), |at| {
            at.saturating_duration_since(Instant::now()).min(Duration::from_secs(1))
        });
        match tokio::time::timeout(wait, output_rx.recv()).await {
            Ok(Some(message)) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                let json = serde_json::to_vec(&message)?;
                let digest = keccak256(&json);
                writeln!(
                    out,
                    "{}\t{now}\t{}\t{}",
                    message.sequence_number,
                    json.len(),
                    alloy_primitives::hex::encode(&digest[..8])
                )?;
                count += 1;
                if message.sequence_number < max_seq {
                    out_of_order += 1;
                }
                max_seq = max_seq.max(message.sequence_number);
            }
            Ok(None) => break,
            Err(_) => {}
        }
        let now = Instant::now();
        if now >= report_at {
            out.flush()?;
            reth_tracing::tracing::info!(
                target: "arb-reth",
                count,
                max_seq,
                out_of_order,
                resume = resume.load(std::sync::atomic::Ordering::Acquire),
                "feed-probe: progress"
            );
            report_at = now + Duration::from_secs(30);
        }
        if deadline.is_some_and(|at| now >= at) {
            break;
        }
    }
    out.flush()?;
    reth_tracing::tracing::info!(target: "arb-reth", count, max_seq, out_of_order, "feed-probe: done");
    Ok(())
}
