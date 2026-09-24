//! Native payload-builder integration tests over testnode replay fixtures.
#![allow(missing_docs)]

mod tests {
    use arb_reth_engine::{
        ArbBuildAccel, ArbEngineDriver, ArbEngineTuning, ArbPrewarm, ArbTxExecutionKind,
        ArbTxLogBroadcaster, ArbTxPrecompute,
    };
    use arb_reth_evm::ArbEvmConfig;

    use std::sync::Arc;
    use std::vec::Vec;

    use alloy_consensus::Header;
    use alloy_primitives::{U256, address};
    use arbitrum_alloy_sequencer::sequencer::feed::BroadcastFeedMessage;

    use reth_primitives_traits::SealedHeader;
    use reth_provider::HeaderProvider;
    use reth_provider::providers::BlockchainProvider;
    use reth_provider::test_utils::create_test_provider_factory_with_node_types;
    use reth_tasks::Runtime;

    use arb_reth_node::ArbNode;

    /// Concrete test factory type (temp MDBX over `ArbNode` types).
    type TestDb = Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>;
    type TestNodeTypes = reth_node_api::NodeTypesWithDBAdapter<ArbNode, TestDb>;
    type TestFactory = reth_provider::ProviderFactory<TestNodeTypes>;

    /// The testnode ArbOS chain spec (ArbOS v40, chain 412346) shared by both fixtures.
    fn testnode_spec() -> Arc<reth_chainspec::ChainSpec> {
        use arb_reth_node::arb_chain_spec;
        use arb_revm::arbos_init::ArbosInitConfig;
        const CHAIN_CONFIG: &[u8] =
            include_bytes!("../tests/fixtures/testnode_l2_chain_config.json");
        let init = ArbosInitConfig {
            initial_arbos_version: 40,
            initial_chain_owner: address!("5E1497dD1f08C87b2d8FE23e9AAB6c1De833D927"),
            chain_id: U256::from(412346u64),
            genesis_block_number: 0,
            initial_l1_base_fee: U256::from(167u64),
            serialized_chain_config: CHAIN_CONFIG.to_vec(),
            debug_precompiles: true,
        };
        Arc::new(arb_chain_spec(&init).expect("build ArbOS chain spec"))
    }

    /// Gate (plain state): native payload construction over a v1/plain-state base.
    #[tokio::test(flavor = "multi_thread")]
    async fn engine_tree_tier1_replay() {
        let factory = create_test_provider_factory_with_node_types::<ArbNode>(testnode_spec());
        reth_db_common::init::init_genesis(&factory).expect("init ArbOS genesis block 0");
        drive_replay_native(factory, 412346, ArbEngineTuning::reth_defaults()).await;
    }

    /// Gate (hashed-only / storage v2): the mainnet-shaped base where hashed-state tables are
    /// canonical (no `PlainAccountState`), exactly like the imported Arb One snapshot. The
    /// plain-state gate above does not exercise the hashed read path; this proves the native
    /// payload builder and engine-owned sparse trie task read the hashed tables correctly.
    #[tokio::test(flavor = "multi_thread")]
    async fn engine_tree_tier1_replay_v2_hashed() {
        let factory = storage_v2_factory();
        drive_replay_native(factory, 412346, ArbEngineTuning::reth_defaults()).await;
    }

    /// Gate the sparse state-root task over the same Storage V2 replay fixture.
    #[tokio::test(flavor = "multi_thread")]
    async fn engine_tree_tier1_replay_v2_hashed_sparse() {
        let factory = storage_v2_factory();
        let tuning = ArbEngineTuning::from_tree_config(
            ArbEngineTuning::reth_defaults()
                .to_tree_config()
                .with_share_sparse_trie_with_payload_builder(true),
        );
        drive_replay_native(factory, 412346, tuning).await;
    }

    /// Same gate with both big-block accelerations on: every message is precomputed (and waited
    /// for, so the builder really uses it) and every block is prewarmed through the shared
    /// execution cache. Block hashes and state roots must stay identical to Nitro's.
    #[tokio::test(flavor = "multi_thread")]
    async fn engine_tree_tier1_replay_v2_hashed_sparse_accel() {
        let factory = storage_v2_factory();
        let tuning = ArbEngineTuning::from_tree_config(
            ArbEngineTuning::reth_defaults()
                .to_tree_config()
                .with_share_sparse_trie_with_payload_builder(true),
        );
        let accel = ArbBuildAccel {
            precompute: Some(ArbTxPrecompute::new(412346, 2, Vec::new())),
            prewarm: Some(ArbPrewarm::new(2, 1, Vec::new())),
        };
        drive_replay_native_with(factory, 412346, tuning, accel).await;
    }

    fn storage_v2_factory() -> TestFactory {
        // Emit a storage-v2 DB (hashed-state canonical, `PackedKeyAdapter`), mirroring the importer.
        use reth_db_api::models::StorageSettings;
        use reth_provider::{MetadataWriter, StorageSettingsCache};

        let factory = create_test_provider_factory_with_node_types::<ArbNode>(testnode_spec());
        factory.set_storage_settings_cache(StorageSettings::v2());
        {
            let provider_rw = factory.provider_rw().expect("provider_rw");
            provider_rw
                .write_storage_settings(StorageSettings::v2())
                .expect("write storage settings");
            provider_rw.commit().expect("commit storage settings");
        }
        reth_db_common::init::init_genesis_with_settings_and_validate(
            &factory,
            StorageSettings::v2(),
            true,
        )
        .expect("init ArbOS genesis (v2 hashed-canonical)");
        factory
    }

    async fn drive_replay_native(factory: TestFactory, chain_id: u64, tuning: ArbEngineTuning) {
        drive_replay_native_with(factory, chain_id, tuning, ArbBuildAccel::default()).await;
    }

    async fn drive_replay_native_with(
        factory: TestFactory,
        chain_id: u64,
        tuning: ArbEngineTuning,
        accel: ArbBuildAccel,
    ) {
        const TARGET: u64 = 17;
        const FEED: &str = include_str!("../tests/fixtures/testnode_feed_seq0_17.ndjson");
        const BLOCKS: &str = include_str!("../tests/fixtures/testnode_blocks_0_17.json");

        let expected: Vec<serde_json::Value> = serde_json::from_str(BLOCKS).unwrap();
        let genesis_tip: SealedHeader<Header> = {
            let provider = factory.provider().expect("provider");
            let header = provider
                .sealed_header(0)
                .expect("read genesis")
                .expect("genesis header");
            drop(provider);
            header
        };
        let provider = BlockchainProvider::new(factory.clone()).expect("BlockchainProvider::new");
        let canonical = provider.canonical_in_memory_state();
        let tx_log_stream = ArbTxLogBroadcaster::new();
        let mut tx_events = tx_log_stream.subscribe();
        let mut driver = ArbEngineDriver::<TestNodeTypes>::spawn(
            factory,
            provider,
            ArbEvmConfig::new(chain_id),
            chain_id,
            genesis_tip,
            0,
            canonical,
            Runtime::test(),
            tuning,
            None,
            Some(tx_log_stream),
            reth_tokio_util::EventSender::default(),
            accel.clone(),
        )
        .expect("spawn native payload driver");

        let messages = FEED
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<BroadcastFeedMessage>(line).expect("feed message"))
            .filter(|message| message.sequence_number > 0 && message.sequence_number <= TARGET)
            .collect::<Vec<_>>();
        let message_count = messages.len();
        let mut canonicalized = Vec::with_capacity(message_count);
        for (index, message) in messages.into_iter().enumerate() {
            let number = message.sequence_number;
            if let Some(precompute) = accel.precompute.as_ref() {
                precompute.submit(message.clone());
                // Batch-posting reports (kind 13) are never precomputed; other messages are, so
                // the builder below really consumes the precomputed result.
                if message.message_with_meta_data.l1_incoming_message.header.kind != 13 {
                    let _ = precompute.wait_ready(number, std::time::Duration::from_secs(2));
                }
            }
            let defer_tail = index + 1 < message_count;
            let hash = driver
                .advance_with_applied_overlap(&message, defer_tail, |sequence_number, _| {
                    canonicalized.push(sequence_number);
                })
                .await
                .expect("native overlap advance");
            let header = driver.tip().header();
            let expected_block = &expected[number as usize];
            assert_eq!(
                format!("{hash:#x}"),
                expected_block["hash"].as_str().expect("expected hash"),
                "block {number} hash"
            );
            assert_eq!(
                format!("{:#x}", header.state_root),
                expected_block["stateRoot"]
                    .as_str()
                    .expect("expected state root"),
                "block {number} state root"
            );

            // Exercise the actual producer, not only the IPC encoder. The extra notifications
            // must bracket every included transaction without changing canonical replay hashes.
            let mut events = Vec::new();
            loop {
                match tx_events.try_recv() {
                    Ok(event) => events.push(event),
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                    Err(error) => panic!("block {number} lost transaction events: {error}"),
                }
            }
            assert!(
                events.len() >= 3,
                "block {number} must include both markers"
            );
            assert!(events.iter().all(|event| event.block_number == number));
            let manifest = &events[0];
            assert_eq!(manifest.kind, ArbTxExecutionKind::FeedTxs);
            assert_eq!(manifest.transaction_index, manifest.feed_txs.len() as u64);
            assert!(manifest.transaction_hash.is_zero());
            assert!(manifest.frontier_id.is_zero());
            let end = events.last().unwrap();
            assert_eq!(end.kind, ArbTxExecutionKind::EndBlock);
            assert!(end.transaction_hash.is_zero());
            assert!(end.frontier_id.is_zero());
            let transactions = &events[1..events.len() - 1];
            assert_eq!(end.transaction_index, transactions.len() as u64);
            assert_eq!(transactions[0].kind, ArbTxExecutionKind::StartBlock);
            assert_eq!(
                transactions.iter().map(|event| event.gas_used).sum::<u64>(),
                header.gas_used,
                "streamed transactions must account for the entire canonical block"
            );
            for (index, event) in transactions.iter().enumerate() {
                assert_eq!(event.transaction_index, index as u64);
                assert!(!event.frontier_id.is_zero());
                assert!(!event.transaction_hash.is_zero());
                assert!(matches!(
                    event.kind,
                    ArbTxExecutionKind::StartBlock
                        | ArbTxExecutionKind::User
                        | ArbTxExecutionKind::ScheduledRetry
                ));
            }
        }
        assert_eq!(canonicalized, (1..=TARGET).collect::<Vec<_>>());

        driver.shutdown().await;
    }
}
