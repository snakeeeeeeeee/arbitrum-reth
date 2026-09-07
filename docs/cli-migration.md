# CLI migration

`arb-reth node` now uses Reth's native node command. Arbitrum-specific inputs remain available,
while database, engine, RPC, metrics, pruning, and logging settings use Reth's flag names.

Unknown commands and arguments print a link to this guide. The complete current interface is
available through:

```sh
arb-reth node --help
```

## Changed arguments

| Previous argument | Native CLI argument | Notes |
| --- | --- | --- |
| `--chain <chain-config.json>` | `--arb-chain-config <chain-config.json>` | `--chain` is now Reth's chain-spec selector. |
| `--persistence-threshold <N>` | `--engine.persistence-threshold <N>` | The default remains 2 blocks. |
| `--memory-buffer-target <N>` | `--engine.memory-block-buffer-target <N>` | The default remains 0 blocks. |
| `--persistence-backpressure <N>` | `--engine.persistence-backpressure-threshold <N>` | The default remains 16 blocks. |
| `--share-execution-cache-with-payload-builder true` | `--engine.share-execution-cache-with-payload-builder` | Sharing remains enabled by default, so the argument can normally be removed. |
| `--share-sparse-trie-with-payload-builder` | `--engine.share-sparse-trie-with-payload-builder` | Sparse-trie sharing remains opt-in. |
| `--no-fsync` | `--db.sync-mode safe-no-sync` | `--no-fsync` remains as a temporary compatibility alias. |

`--datadir`, `--metrics`, `--http`, `--http.addr`, `--http.port`, pruning arguments, and the
Arbitrum-specific L1, feed, genesis, snapshot, and MEV arguments keep their existing names.

## RPC changes

HTTP and WebSocket servers now use Reth's native settings. Enable them independently:

```sh
arb-reth node \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --ws --ws.addr 127.0.0.1 --ws.port 8546
```

Use `--http.api` and `--ws.api` to select namespaces. Local IPC follows Reth's default behavior;
pass `--ipcdisable` when it is not wanted. Use `--rpc.gascap max` when RPC simulations must not be
limited by Reth's default call gas cap.

## Example

Before:

```sh
arb-reth node \
  --datadir /data/arb \
  --chain chain-config.json \
  --persistence-threshold 128 \
  --memory-buffer-target 64 \
  --persistence-backpressure 512 \
  --share-sparse-trie-with-payload-builder \
  --no-fsync \
  --http
```

After:

```sh
arb-reth node \
  --datadir /data/arb \
  --arb-chain-config chain-config.json \
  --engine.persistence-threshold 128 \
  --engine.memory-block-buffer-target 64 \
  --engine.persistence-backpressure-threshold 512 \
  --engine.share-sparse-trie-with-payload-builder \
  --db.sync-mode safe-no-sync \
  --http
```

The non-node tools keep their command structure: `snapshot`, `genesis`, `rewind`, and
`dump-blocks`.

## Robinhood MEV fork

The server additions remain available with the native CLI: `--mev-tx-log-ipc`, counted
`--feed-source IP=COUNT`, `--feed-spare-ip`, `--feed-rotate-lag-ms`, and
`--feed-rotate-window-secs`. IPC version 2 retains the kind-3 EndBlock and kind-4 FeedTxs
frames consumed by the colocated bot. These events are provisional; see the
[IPC protocol](mev-tx-log-ipc.md) for their validity and reconnect requirements.

To retain the operator's six-million-block receipts and state-history window, pass the
explicit pruning arguments instead of the shorter `--full` preset:

```sh
arb-reth node ... \
  --prune.receipts.distance 6000000 \
  --prune.account-history.distance 6000000 \
  --prune.storage-history.distance 6000000 \
  --prune.sender-recovery.full \
  --prune.block-interval 5
```

The launcher uses Reth's effective pruning configuration after CLI and `reth.toml` are
merged. Verify the startup `history pruning enabled` log shows the intended distances.
Increasing retention does not restore history already pruned from an existing database.

Server startup scripts must also migrate the old engine options listed above; merging
the source does not rewrite those scripts or change a running node.
