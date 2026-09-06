//! Best-effort local IPC for per-transaction ArbOS execution logs.
//!
//! The socket uses a compact, length-delimited binary frame. It is intentionally separate from
//! RPC: callers receive a transaction as soon as its EVM execution completes, before receipt/
//! state-root hashing and before the enclosing block becomes canonical.

use std::{
    fs,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use arb_reth_engine::{ArbTxExecutionKind, ArbTxLogBroadcaster, ArbTxLogEvent};
use eyre::{Context, Result, bail};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    sync::broadcast,
};

/// A local Unix-domain socket server for [`ArbTxLogEvent`] values.
pub(crate) struct MevTxLogIpc {
    listener: UnixListener,
    path: PathBuf,
    broadcaster: ArbTxLogBroadcaster,
}

impl MevTxLogIpc {
    /// Binds the requested local socket, replacing a stale socket from a previous shutdown.
    pub(crate) fn bind(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path).wrap_err_with(|| {
            format!("bind MEV transaction-log IPC socket at {}", path.display())
        })?;
        Ok(Self {
            listener,
            path,
            broadcaster: ArbTxLogBroadcaster::new(),
        })
    }

    /// Returns the execution-side publisher passed to the native payload builder.
    pub(crate) fn broadcaster(&self) -> ArbTxLogBroadcaster {
        self.broadcaster.clone()
    }

    /// Socket location, used only for the launch log.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Serves local clients until the runtime begins graceful shutdown.
    pub(crate) async fn serve(self, mut shutdown: reth_tasks::shutdown::GracefulShutdown) {
        loop {
            tokio::select! {
                guard = &mut shutdown => {
                    drop(guard);
                    break;
                }
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let events = self.broadcaster.subscribe();
                        tokio::spawn(stream_client(stream, events));
                    }
                    Err(error) => {
                        reth_tracing::tracing::warn!(
                            target: "arb-reth::mev",
                            %error,
                            path = %self.path.display(),
                            "MEV transaction-log IPC accept failed"
                        );
                    }
                },
            }
        }
    }
}

impl Drop for MevTxLogIpc {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            reth_tracing::tracing::warn!(
                target: "arb-reth::mev",
                %error,
                path = %self.path.display(),
                "failed to remove MEV transaction-log IPC socket"
            );
        }
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).wrap_err_with(|| format!("inspect {}", path.display())),
    };
    if !metadata.file_type().is_socket() {
        bail!(
            "refusing to replace non-socket MEV transaction-log IPC path {}",
            path.display()
        );
    }
    fs::remove_file(path).wrap_err_with(|| format!("remove stale socket {}", path.display()))
}

async fn stream_client(mut stream: UnixStream, mut events: broadcast::Receiver<ArbTxLogEvent>) {
    loop {
        let event = match events.recv().await {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                reth_tracing::tracing::warn!(
                    target: "arb-reth::mev",
                    skipped,
                    "disconnecting slow MEV transaction-log IPC client"
                );
                return;
            }
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let encoded = match encode_event(&event) {
            Ok(encoded) => encoded,
            Err(error) => {
                reth_tracing::tracing::warn!(
                    target: "arb-reth::mev",
                    %error,
                    "failed to encode MEV transaction-log event"
                );
                continue;
            }
        };
        if stream.write_all(&encoded).await.is_err() {
            return;
        }
    }
}

/// Version of the binary frame format documented in `docs/mev-tx-log-ipc.md`.
const FRAME_VERSION: u8 = 2;
const FIXED_BODY_LEN: usize = 96;
const MAX_LOG_TOPICS: usize = 4;
/// Fixed bytes of one kind-4 manifest entry before its calldata: 20-byte `to` + u32 length.
const FEED_TX_ENTRY_PREFIX_LEN: usize = 24;

fn encode_event(event: &ArbTxLogEvent) -> Result<Vec<u8>> {
    let log_count = u32::try_from(event.logs.len())
        .map_err(|_| eyre::eyre!("MEV transaction-log event has too many logs"))?;
    let mut body_len = FIXED_BODY_LEN;
    for log in &event.logs {
        let topics = log.data.topics();
        if topics.len() > MAX_LOG_TOPICS {
            bail!("MEV transaction-log event has too many log topics")
        }
        let data_len = u32::try_from(log.data.data.len())
            .map_err(|_| eyre::eyre!("MEV transaction-log log data exceeds 4 GiB"))?;
        body_len = body_len
            .checked_add(25 + topics.len() * B256::len_bytes() + data_len as usize)
            .ok_or_else(|| eyre::eyre!("MEV transaction-log frame length overflow"))?;
    }
    // Kind 4 reuses the fixed prefix and appends `(to, calldata)` entries in place of logs. Keep
    // the frame unambiguous: a manifest never carries logs, no other kind carries entries, and the
    // entry count in the `transactionIndex` slot must match what follows.
    let is_feed_txs = matches!(event.kind, ArbTxExecutionKind::FeedTxs);
    if is_feed_txs && !event.logs.is_empty() {
        bail!("MEV feed-transactions event must not carry logs")
    }
    if !is_feed_txs && !event.feed_txs.is_empty() {
        bail!("MEV transaction-log event must not carry feed transactions")
    }
    if is_feed_txs && event.transaction_index != event.feed_txs.len() as u64 {
        bail!("MEV feed-transactions event count does not match its entries")
    }
    for (_, calldata) in &event.feed_txs {
        let calldata_len = u32::try_from(calldata.len())
            .map_err(|_| eyre::eyre!("MEV feed-transactions calldata exceeds 4 GiB"))?;
        body_len = body_len
            .checked_add(FEED_TX_ENTRY_PREFIX_LEN + calldata_len as usize)
            .ok_or_else(|| eyre::eyre!("MEV transaction-log frame length overflow"))?;
    }
    let frame_len = u32::try_from(body_len)
        .map_err(|_| eyre::eyre!("MEV transaction-log frame exceeds 4 GiB"))?;

    let mut encoded = Vec::with_capacity(4 + body_len);
    encoded.extend_from_slice(&frame_len.to_be_bytes());
    encoded.push(FRAME_VERSION);
    encoded.push(match event.kind {
        ArbTxExecutionKind::StartBlock => 0,
        ArbTxExecutionKind::User => 1,
        ArbTxExecutionKind::ScheduledRetry => 2,
        ArbTxExecutionKind::EndBlock => 3,
        ArbTxExecutionKind::FeedTxs => 4,
    });
    encoded.push(u8::from(event.success));
    encoded.push(0); // Reserved for future flags.
    encoded.extend_from_slice(&event.block_number.to_be_bytes());
    encoded.extend_from_slice(&event.transaction_index.to_be_bytes());
    encoded.extend_from_slice(&event.gas_used.to_be_bytes());
    encoded.extend_from_slice(event.transaction_hash.as_slice());
    encoded.extend_from_slice(event.frontier_id.as_slice());
    encoded.extend_from_slice(&log_count.to_be_bytes());
    for log in &event.logs {
        let topics = log.data.topics();
        encoded.extend_from_slice(log.address.as_slice());
        encoded.push(topics.len() as u8);
        let data_len = u32::try_from(log.data.data.len())
            .expect("validated while calculating MEV transaction-log frame length");
        encoded.extend_from_slice(&data_len.to_be_bytes());
        for topic in topics {
            encoded.extend_from_slice(topic.as_slice());
        }
        encoded.extend_from_slice(&log.data.data);
    }
    for (to, calldata) in &event.feed_txs {
        encoded.extend_from_slice(to.as_slice());
        let calldata_len = u32::try_from(calldata.len())
            .expect("validated while calculating MEV transaction-log frame length");
        encoded.extend_from_slice(&calldata_len.to_be_bytes());
        encoded.extend_from_slice(calldata);
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, Log, LogData, b256};
    use tokio::io::AsyncReadExt;

    #[test]
    fn encodes_one_binary_transaction_event() {
        let event = ArbTxLogEvent {
            block_number: 42,
            transaction_index: 3,
            transaction_hash: b256!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            frontier_id: B256::repeat_byte(0xcc),
            kind: ArbTxExecutionKind::User,
            success: true,
            gas_used: 21_000,
            logs: vec![Log {
                address: Address::repeat_byte(0x11),
                data: LogData::new_unchecked(
                    vec![b256!(
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    )],
                    Bytes::from_static(&[0x12, 0x34]),
                ),
            }],
            feed_txs: Vec::new(),
        };

        let encoded = encode_event(&event).expect("event encodes");
        assert_eq!(
            u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
            encoded.len() - 4
        );
        assert_eq!(encoded[4], FRAME_VERSION);
        assert_eq!(encoded[5], 1); // user
        assert_eq!(encoded[6], 1); // success
        assert_eq!(u64::from_be_bytes(encoded[8..16].try_into().unwrap()), 42);
        assert_eq!(u64::from_be_bytes(encoded[16..24].try_into().unwrap()), 3);
        assert_eq!(
            u64::from_be_bytes(encoded[24..32].try_into().unwrap()),
            21_000
        );
        assert_eq!(&encoded[64..96], B256::repeat_byte(0xcc).as_slice());
        assert_eq!(u32::from_be_bytes(encoded[96..100].try_into().unwrap()), 1);
        assert_eq!(&encoded[100..120], Address::repeat_byte(0x11).as_slice());
        assert_eq!(encoded[120], 1);
        assert_eq!(u32::from_be_bytes(encoded[121..125].try_into().unwrap()), 2);
        assert_eq!(&encoded[157..159], [0x12, 0x34]);
    }

    #[test]
    fn encodes_feed_transactions_manifest() {
        let calldata_a = Bytes::from_static(&[0xa9, 0x05, 0x9c, 0xbb, 0x01]);
        let calldata_b = Bytes::from_static(&[0xde, 0xad]);
        let event = ArbTxLogEvent {
            block_number: 42,
            transaction_index: 2,
            transaction_hash: B256::ZERO,
            frontier_id: B256::ZERO,
            kind: ArbTxExecutionKind::FeedTxs,
            success: false,
            gas_used: 0,
            logs: Vec::new(),
            feed_txs: vec![
                (Address::repeat_byte(0x11), calldata_a.clone()),
                // Contract creation: `to` is all zeros.
                (Address::ZERO, calldata_b.clone()),
            ],
        };

        let encoded = encode_event(&event).expect("event encodes");
        // Length prefix + 96-byte fixed prefix + (24 + 5) + (24 + 2).
        assert_eq!(encoded.len(), 4 + 96 + 29 + 26);
        assert_eq!(
            u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize,
            encoded.len() - 4
        );
        assert_eq!(encoded[4], FRAME_VERSION);
        assert_eq!(encoded[5], 4); // feed txs
        assert_eq!(encoded[6], 0); // success
        assert_eq!(encoded[7], 0); // flags
        assert_eq!(u64::from_be_bytes(encoded[8..16].try_into().unwrap()), 42);
        // Transaction count rides in the transactionIndex slot.
        assert_eq!(u64::from_be_bytes(encoded[16..24].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(encoded[24..32].try_into().unwrap()), 0);
        assert_eq!(&encoded[32..64], B256::ZERO.as_slice());
        assert_eq!(&encoded[64..96], B256::ZERO.as_slice());
        assert_eq!(u32::from_be_bytes(encoded[96..100].try_into().unwrap()), 0);
        // Entry 0: to, calldata length, calldata.
        assert_eq!(&encoded[100..120], Address::repeat_byte(0x11).as_slice());
        assert_eq!(u32::from_be_bytes(encoded[120..124].try_into().unwrap()), 5);
        assert_eq!(&encoded[124..129], calldata_a.as_ref());
        // Entry 1.
        assert_eq!(&encoded[129..149], Address::ZERO.as_slice());
        assert_eq!(u32::from_be_bytes(encoded[149..153].try_into().unwrap()), 2);
        assert_eq!(&encoded[153..155], calldata_b.as_ref());
    }

    #[test]
    fn rejects_malformed_feed_transactions_events() {
        let base = ArbTxLogEvent {
            block_number: 42,
            transaction_index: 1,
            transaction_hash: B256::ZERO,
            frontier_id: B256::ZERO,
            kind: ArbTxExecutionKind::FeedTxs,
            success: false,
            gas_used: 0,
            logs: Vec::new(),
            feed_txs: vec![(Address::ZERO, Bytes::new())],
        };
        assert!(encode_event(&base).is_ok());

        // The count in the transactionIndex slot must match the entries.
        let mismatched = ArbTxLogEvent {
            transaction_index: 2,
            ..base.clone()
        };
        assert!(encode_event(&mismatched).is_err());

        // A manifest never carries logs.
        let with_logs = ArbTxLogEvent {
            logs: vec![Log {
                address: Address::ZERO,
                data: LogData::new_unchecked(Vec::new(), Bytes::new()),
            }],
            ..base.clone()
        };
        assert!(encode_event(&with_logs).is_err());

        // Only the manifest kind carries entries.
        let wrong_kind = ArbTxLogEvent {
            kind: ArbTxExecutionKind::User,
            ..base
        };
        assert!(encode_event(&wrong_kind).is_err());
    }

    #[test]
    fn only_replaces_an_existing_socket() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("mev.sock");
        fs::write(&path, b"not a socket").expect("write regular file");

        assert!(remove_stale_socket(&path).is_err());
        assert!(path.exists());
    }

    #[test]
    fn rejects_more_than_four_topics() {
        let event = ArbTxLogEvent {
            block_number: 42,
            transaction_index: 3,
            transaction_hash: B256::ZERO,
            frontier_id: B256::repeat_byte(0xcc),
            kind: ArbTxExecutionKind::User,
            success: true,
            gas_used: 21_000,
            logs: vec![Log {
                address: Address::ZERO,
                data: LogData::new_unchecked(vec![B256::ZERO; 5], Bytes::new()),
            }],
            feed_txs: Vec::new(),
        };

        assert!(encode_event(&event).is_err());
    }

    #[tokio::test]
    async fn connected_client_receives_transaction_event() {
        let broadcaster = ArbTxLogBroadcaster::new();
        let receiver = broadcaster.subscribe();
        let (writer, reader) = UnixStream::pair().expect("Unix stream pair");
        let client = tokio::spawn(stream_client(writer, receiver));

        broadcaster.publish(ArbTxLogEvent {
            block_number: 42,
            transaction_index: 3,
            transaction_hash: B256::ZERO,
            frontier_id: B256::repeat_byte(0xcc),
            kind: ArbTxExecutionKind::User,
            success: true,
            gas_used: 21_000,
            logs: Vec::new(),
            feed_txs: Vec::new(),
        });

        let mut length = [0; 4];
        let mut reader = reader;
        reader
            .read_exact(&mut length)
            .await
            .expect("read frame length");
        let mut body = vec![0; u32::from_be_bytes(length) as usize];
        reader.read_exact(&mut body).await.expect("read frame");
        assert_eq!(body[4..12], 42u64.to_be_bytes());
        assert_eq!(body[12..20], 3u64.to_be_bytes());

        drop(broadcaster);
        client.await.expect("client task exits");
    }
}
