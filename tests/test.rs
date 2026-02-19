#[cfg(test)]
mod tests {
    use bitcoinkernel::notifications::types::BlockValidationState;
    use bitcoinkernel::state::chainstate::ProcessBlockHeaderResult;
    use bitcoinkernel::{
        prelude::*, verify, Block, BlockHash, BlockHeader, BlockSpentOutputs, BlockTreeEntry,
        BlockValidationStateRef, ChainParams, ChainType, ChainstateManager,
        ChainstateManagerBuilder, Coin, Context, ContextBuilder, KernelError, Log, Logger,
        Opcode, PrecomputedTransactionData, ScriptDebugger, ScriptExecError, ScriptPhase,
        ScriptPubkey, ScriptVerifyError,
        Transaction, TransactionSpentOutputs, TxIn, TxOut, ValidationMode, VERIFY_ALL,
        VERIFY_ALL_PRE_TAPROOT, VERIFY_TAPROOT, VERIFY_WITNESS,
    };
    use bitcoinkernel::trace_verify;
    use libbitcoinkernel_sys::btck_ScriptVerificationFlags;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Once};
    use tempdir::TempDir;

    struct TestLog {}

    impl Log for TestLog {
        fn log(&self, message: &str) {
            log::info!(
                target: "libbitcoinkernel", 
                "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
        }
    }

    static START: Once = Once::new();
    static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

    fn setup_logging() {
        let _ = env_logger::Builder::from_default_env()
            .is_test(true)
            .try_init();
        unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(TestLog {}).unwrap()) };
    }

    fn create_context() -> Context {
        fn pow_handler(_entry: BlockTreeEntry, _block: Block) {
            log::info!("New PoW valid block!");
        }

        fn connected_handler(_block: Block, _entry: BlockTreeEntry) {
            log::info!("Block connected!");
        }

        fn disconnected_handler(_block: Block, _entry: BlockTreeEntry) {
            log::info!("Block disconnected!");
        }

        let builder = ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .with_block_tip_notification(|_state, _block_tip, _verification_progress| {
                log::info!("Received block tip.");
            })
            .with_header_tip_notification(|_state, height, timestamp, _presync| {
                assert!(timestamp > 0);
                log::info!(
                    "Received header tip at height {} and time {}",
                    height,
                    timestamp
                );
            })
            .with_progress_notification(|_state, progress, _resume_possible| {
                log::info!("Made progress: {}", progress);
            })
            .with_warning_set_notification(|_warning, message| {
                log::info!("Received warning: {}", message);
            })
            .with_warning_unset_notification(|_warning| {
                log::info!("Unsetting warning.");
            })
            .with_flush_error_notification(|message| {
                log::info!("Flush error! {}", message);
            })
            .with_fatal_error_notification(|message| {
                log::info!("Fatal error! {}", message);
            })
            .with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {
                log::info!("Block checked!");
            })
            .with_new_pow_valid_block_validation(pow_handler)
            .with_block_connected_validation(connected_handler)
            .with_block_disconnected_validation(disconnected_handler);

        builder.build().unwrap()
    }

    fn testing_setup() -> (Arc<Context>, String) {
        START.call_once(|| {
            setup_logging();
        });
        let context = Arc::new(create_context());

        let temp_dir = TempDir::new("test_chainman_regtest").unwrap();
        let data_dir = temp_dir.path();
        (context, data_dir.to_str().unwrap().to_string())
    }

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap().to_vec());
        }
        lines
    }

    fn setup_chainman_with_blocks(
        context: &Arc<Context>,
        data_dir: &str,
    ) -> Result<ChainstateManager, KernelError> {
        let blocks_dir = data_dir.to_string() + "/blocks";
        let block_data = read_block_data();

        let chainman = ChainstateManager::new(context, data_dir, &blocks_dir)?;

        for raw_block in block_data.iter() {
            let block = Block::new(raw_block.as_slice())?;
            let result = chainman.process_block(&block);
            assert!(result.is_new_block());
            assert!(!result.is_duplicate());
            assert!(!result.is_rejected());
        }

        Ok(chainman)
    }

    #[test]
    fn test_reindex() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        {
            let block_data = read_block_data();

            let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
                .unwrap()
                .build()
                .unwrap();
            for raw_block in block_data.iter() {
                let block = Block::try_from(raw_block.as_slice()).unwrap();
                let result = chainman.process_block(&block);
                assert!(result.is_new_block());
                assert!(!result.is_duplicate());
                assert!(!result.is_rejected());
            }
        }

        let chainman_builder = ChainstateManager::builder(&context, &data_dir, &blocks_dir)
            .unwrap()
            .wipe_db(false, true)
            .unwrap();

        let chainman = chainman_builder.build().unwrap();
        chainman.import_blocks().unwrap();
        drop(chainman);
    }

    #[test]
    fn test_invalid_block() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        for _ in 0..10 {
            let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
                .unwrap()
                .build()
                .unwrap();

            // Not a block
            let block = Block::try_from(hex::decode("deadbeef").unwrap().as_slice());
            assert!(matches!(block, Err(KernelError::Internal(_))));
            drop(block);

            // Invalid block
            let block_1 = Block::new(hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000").unwrap().as_slice()
            )
            .unwrap();
            let result = chainman.process_block(&block_1);
            assert!(result.is_rejected());
            assert!(!result.is_new_block());
            assert!(!result.is_duplicate())
        }
    }

    #[test]
    fn test_process_data() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .build()
            .unwrap();

        for raw_block in block_data.iter() {
            let block = Block::try_from(raw_block.as_slice()).unwrap();
            let result = chainman.process_block(&block);
            assert!(result.is_new_block());
            assert!(!result.is_rejected());
            assert!(!result.is_duplicate());
        }
    }

    #[test]
    fn test_validate_any() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .build()
            .unwrap();

        chainman.import_blocks().unwrap();
        let block_2 = Block::try_from(block_data[1].clone().as_slice()).unwrap();
        let result = chainman.process_block(&block_2);
        assert!(result.is_rejected());
        assert!(!result.is_new_block());
        assert!(!result.is_duplicate());
    }

    #[test]
    fn test_logger() {
        let (_, _) = testing_setup();

        let logger_1 = Some(Logger::new(TestLog {}).unwrap());
        let logger_2 = Some(Logger::new(TestLog {}).unwrap());
        let logger_3 = Some(Logger::new(TestLog {}).unwrap());

        drop(logger_1);

        drop(logger_2);

        drop(logger_3);
    }

    #[test]
    fn script_verify_test() {
        // a random old-style transaction from the blockchain
        verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random segwit transaction from the blockchain using P2SH
        verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            1900000, 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random segwit transaction from the blockchain using native segwit
        verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random old-style transaction from the blockchain - WITH WRONG SIGNATURE for the address
        assert!(matches!(verify_test(
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ff",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0 , vec![], VERIFY_ALL_PRE_TAPROOT
        ), Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))));

        // a random segwit transaction from the blockchain using native segwit - WITH WRONG SEGWIT
        assert!(matches!(verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58f",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ), Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))));

        // a random taproot transaction
        let spent = "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";
        let spending  = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
        let spent_script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let outputs: Vec<TxOut> = vec![TxOut::new(&spent_script_pubkey, 88480)];
        verify_test(spent, spending, 88480, 0, outputs, VERIFY_ALL).unwrap();
        assert!(matches!(
            verify_test(spent, spending, 88480, 0, vec![], VERIFY_ALL),
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::SpentOutputsRequired
            ))
        ));
    }

    #[test]
    fn test_verify_input_validation() {
        let script_data =
            hex::decode("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac").unwrap();
        let script_pubkey = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_hex = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        let tx = Transaction::new(hex::decode(tx_hex).unwrap().as_slice()).unwrap();
        let dummy_output = TxOut::new(&script_pubkey, 100000);
        let tx_data =
            PrecomputedTransactionData::new(&tx, std::slice::from_ref(&dummy_output)).unwrap();

        // tx_index out of bounds
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            999,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex))
        ));

        let wrong_spent_outputs = vec![dummy_output.clone(), dummy_output.clone()];
        assert!(matches!(
            PrecomputedTransactionData::new(&tx, &wrong_spent_outputs),
            Err(KernelError::MismatchedOutputsSize)
        ));

        // Test Invalid flags
        let result = verify(&script_pubkey, Some(0), &tx, 0, Some(0xFFFFFFFF), &tx_data);
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags))
        ));

        // Test Invalid flags combination
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_WITNESS),
            &tx_data,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::InvalidFlagsCombination
            ))
        ));

        // Test Spent outputs required
        let tx_data_invalid = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_TAPROOT),
            &tx_data_invalid,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::SpentOutputsRequired
            ))
        ));
    }

    #[test]
    fn test_header_validation() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(&context, &data_dir, &blocks_dir).unwrap();

        for raw_block in block_data.iter() {
            let block = Block::new(raw_block.as_slice()).unwrap();
            let result = chainman.process_block_header(&block.header());
            match result {
                ProcessBlockHeaderResult::Success(state) => {
                    assert_eq!(state.mode(), ValidationMode::Valid);
                }
                _ => assert!(false),
            };
        }
    }

    #[test]
    fn test_chain_operations() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let chain = chainman.active_chain();

        let genesis = chain.at_height(0).unwrap();
        assert_eq!(genesis.height(), 0);
        let genesis_hash = genesis.block_hash();

        let tip = chain.tip();
        assert_eq!(tip.height(), chain.height());
        let tip_height = tip.height();
        let tip_hash = tip.block_hash();

        assert!(tip_height > 0);
        assert_ne!(genesis_hash, tip_hash);

        let genesis_via_height = chain.at_height(0).unwrap();
        assert_eq!(genesis_via_height.height(), 0);
        assert_eq!(genesis_via_height.block_hash(), genesis_hash);

        let tip_via_height = chain.at_height(tip_height as usize).unwrap();
        assert_eq!(tip_via_height.height(), tip_height);
        assert_eq!(tip_via_height.block_hash(), tip_hash);

        let invalid_entry = chain.at_height(9999);
        assert!(invalid_entry.is_none());

        assert!(chain.contains(&genesis));
        assert!(chain.contains(&tip));

        let mut last_height = 0;
        let mut last_block_index: Option<BlockTreeEntry> = None;

        for (height, current_block_index) in chain.iter().enumerate() {
            assert_eq!(current_block_index.height(), height.try_into().unwrap());
            assert!(chain.contains(&current_block_index));
            last_height = height;
            last_block_index = Some(current_block_index);
        }

        assert_eq!(last_height, tip_height as usize);
        assert_eq!(last_block_index.unwrap().block_hash(), tip_hash);
    }

    #[test]
    fn test_block_transactions_iterator() {
        let block_data = read_block_data();

        let block = Block::try_from(block_data[5].as_slice()).unwrap();

        let tx_count_via_iterator = block.transactions().count();
        assert_eq!(tx_count_via_iterator, block.transaction_count());

        let txs: Vec<_> = block.transactions().collect();
        assert_eq!(txs.len(), block.transaction_count());

        for (i, tx) in block.transactions().enumerate() {
            let tx_via_index = block.transaction(i).unwrap();
            assert_eq!(tx.input_count(), tx_via_index.input_count());
            assert_eq!(tx.output_count(), tx_via_index.output_count());
        }

        let mut iter = block.transactions();
        let initial_len = iter.len();
        assert_eq!(initial_len, block.transaction_count());

        iter.next();
        assert_eq!(iter.len(), initial_len - 1);

        let non_coinbase_txs: Vec<_> = block.transactions().skip(1).collect();
        assert_eq!(non_coinbase_txs.len(), block.transaction_count() - 1);
    }

    #[test]
    fn test_block_spent_outputs_iterator() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index_tip = active_chain.tip();
        let spent_outputs = chainman.read_spent_outputs(&block_index_tip).unwrap();

        let count_via_iterator = spent_outputs.iter().count();
        assert_eq!(count_via_iterator, spent_outputs.count());

        let tx_spent_vec: Vec<_> = spent_outputs.iter().collect();
        assert_eq!(tx_spent_vec.len(), spent_outputs.count());

        for (i, tx_spent) in spent_outputs.iter().enumerate() {
            let tx_spent_via_index = spent_outputs.transaction_spent_outputs(i).unwrap();
            assert_eq!(tx_spent.count(), tx_spent_via_index.count());
        }

        let mut iter = spent_outputs.iter();
        let initial_len = iter.len();
        assert_eq!(initial_len, spent_outputs.count());

        if initial_len > 0 {
            iter.next();
            assert_eq!(iter.len(), initial_len - 1);
        }
    }

    #[test]
    fn test_transaction_spent_outputs_iterator() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index_tip = active_chain.tip();
        let spent_outputs = chainman.read_spent_outputs(&block_index_tip).unwrap();

        let tx_spent = spent_outputs.transaction_spent_outputs(0).unwrap();

        let count_via_iterator = tx_spent.coins().count();
        assert_eq!(count_via_iterator, tx_spent.count());

        let coins: Vec<_> = tx_spent.coins().collect();
        assert_eq!(coins.len(), tx_spent.count());

        for (i, coin) in tx_spent.coins().enumerate() {
            let coin_via_index = tx_spent.coin(i).unwrap();
            assert_eq!(
                coin.confirmation_height(),
                coin_via_index.confirmation_height()
            );
            assert_eq!(coin.is_coinbase(), coin_via_index.is_coinbase());
        }

        let mut iter = tx_spent.coins();
        let initial_len = iter.len();
        assert_eq!(initial_len, tx_spent.count());

        if initial_len > 0 {
            iter.next();
            assert_eq!(iter.len(), initial_len - 1);
        }

        let coinbase_coins: Vec<_> = tx_spent.coins().filter(|coin| coin.is_coinbase()).collect();

        for coin in coinbase_coins {
            assert!(coin.is_coinbase());
        }
    }

    #[test]
    fn test_nested_iteration() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index = active_chain.at_height(1).unwrap();
        let spent_outputs = chainman.read_spent_outputs(&block_index).unwrap();

        let mut total_coins = 0;
        for tx_spent in spent_outputs.iter() {
            for _ in tx_spent.coins() {
                total_coins += 1;
            }
        }

        let expected_total: usize = spent_outputs.iter().map(|tx_spent| tx_spent.count()).sum();

        assert_eq!(total_coins, expected_total);
    }

    #[test]
    fn test_iterator_with_block_transactions() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index = active_chain.at_height(1).unwrap();
        let block = chainman.read_block_data(&block_index).unwrap();
        let spent_outputs = chainman.read_spent_outputs(&block_index).unwrap();

        for (tx, tx_spent) in block.transactions().skip(1).zip(spent_outputs.iter()) {
            assert_eq!(tx.input_count(), tx_spent.count());
        }
    }

    fn verify_test(
        spent: &str,
        spending: &str,
        amount: i64,
        input: usize,
        outputs: Vec<TxOut>,
        flags: btck_ScriptVerificationFlags,
    ) -> Result<(), KernelError> {
        let spent_script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let spending_tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
        let tx_data = PrecomputedTransactionData::new(&spending_tx, &outputs).unwrap();
        verify(
            &spent_script_pubkey,
            Some(amount),
            &spending_tx,
            input,
            Some(flags),
            &tx_data,
        )?;
        Ok(())
    }

    #[test]
    fn test_traits() {
        fn is_sync<T: Sync>() {}
        fn is_send<T: Send>() {}
        is_sync::<ScriptPubkey>();
        is_send::<ScriptPubkey>();
        is_sync::<ChainParams>(); // compiles only if true
        is_send::<ChainParams>();
        is_sync::<TxOut>();
        is_send::<TxOut>();
        is_sync::<TxIn>();
        is_send::<TxIn>();
        is_sync::<Transaction>();
        is_send::<Transaction>();
        is_sync::<Context>();
        is_send::<Context>();
        is_sync::<Block>();
        is_send::<Block>();
        is_sync::<BlockSpentOutputs>();
        is_send::<BlockSpentOutputs>();
        is_sync::<TransactionSpentOutputs>();
        is_send::<TransactionSpentOutputs>();
        is_sync::<Coin>();
        is_send::<Coin>();
        is_sync::<ChainstateManager>();
        is_send::<ChainstateManager>();
        is_sync::<BlockHash>();
        is_send::<BlockHash>();
        is_sync::<BlockHeader>();
        is_send::<BlockHeader>();
        is_sync::<BlockValidationState>();
        is_send::<BlockValidationState>();

        // is_sync::<Rc<u8>>(); // won't compile, kept as a failure case.
        // is_send::<Rc<u8>>(); // won't compile, kept as a failure case.
    }

    // ─── Script debugger integration tests ──────────────────────────────

    // The ScriptDebugger uses a global callback, so only one can be active at a time.
    // We serialize all debugger tests with this mutex to prevent parallel conflicts.
    use std::sync::Mutex;
    static DEBUGGER_LOCK: Mutex<()> = Mutex::new(());

    // Shared spending transaction used across multiple script-error tests.
    // This is a real P2PKH transaction from the blockchain; the scriptSig contains
    // a valid DER signature + compressed pubkey push, so EvalScript for the scriptSig
    // always succeeds regardless of what scriptPubKey we attach.
    const P2PKH_SPENDING_TX: &str =
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b\
         483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c\
         053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d\
         4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25\
         d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a579\
         99d54d59f67c019e756c88ac6acb0700";

    /// Run `trace_verify` with a custom scriptPubKey hex against `P2PKH_SPENDING_TX`,
    /// assert the trace reports failure, and return the structured error code.
    fn trace_error_test(
        script_pubkey_hex: &str,
        flags: btck_ScriptVerificationFlags,
    ) -> Option<ScriptExecError> {
        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(script_pubkey_hex).unwrap().as_slice()).unwrap();
        let tx =
            Transaction::new(hex::decode(P2PKH_SPENDING_TX).unwrap().as_slice()).unwrap();
        let tx_data =
            PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();
        let trace = trace_verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(flags),
            &tx_data,
        );
        assert!(!trace.success, "expected verification failure");
        trace.script_error
    }

    #[test]
    fn test_trace_verify_p2pkh() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let spent = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";
        let spending = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";

        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
        let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

        let trace = trace_verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );

        assert!(trace.success);
        assert!(!trace.is_empty());

        // P2PKH should have ScriptSig + ScriptPubKey phases
        let phases = trace.phases();
        assert!(phases.len() >= 2, "Expected at least 2 phases, got {}", phases.len());
        assert_eq!(phases[0], ScriptPhase::ScriptSig);
        assert_eq!(phases[1], ScriptPhase::ScriptPubKey);

        // Final stack should have a truthy value
        let final_stack = trace.final_stack().unwrap();
        assert!(!final_stack.is_empty());
    }

    #[test]
    fn test_trace_verify_p2sh_segwit() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let spent = "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87";
        let spending = "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000";

        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
        let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

        let trace = trace_verify(
            &script_pubkey,
            Some(1900000),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );

        assert!(trace.success);
        // P2SH-P2WPKH: should have at least 3 phases (ScriptSig, ScriptPubKey, RedeemScript/WitnessScript)
        let phases = trace.phases();
        assert!(
            phases.len() >= 3,
            "Expected at least 3 phases for P2SH-P2WPKH, got {}",
            phases.len()
        );
    }

    #[test]
    fn test_trace_verify_failure() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Wrong scriptPubKey (last byte changed from 0xac to 0xff)
        let spent = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ff";
        let spending = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";

        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
        let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

        let trace = trace_verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );

        assert!(!trace.success);
        assert!(trace.error.is_some());
        // Last byte 0xff → OP_INVALIDOPCODE → BadOpcode
        assert_eq!(trace.script_error, Some(ScriptExecError::BadOpcode));
        // Should still have captured some steps
        assert!(!trace.is_empty());
    }

    #[test]
    fn test_script_error_bad_opcode() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // scriptPubKey: 0xff = OP_INVALIDOPCODE
        let se = trace_error_test("ff", VERIFY_ALL_PRE_TAPROOT);
        assert_eq!(se, Some(ScriptExecError::BadOpcode));
    }

    #[test]
    fn test_script_error_op_return() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // scriptPubKey: 0x6a = OP_RETURN
        let se = trace_error_test("6a", VERIFY_ALL_PRE_TAPROOT);
        assert_eq!(se, Some(ScriptExecError::OpReturn));
    }

    #[test]
    fn test_script_error_eval_false() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // scriptPubKey: 0x00 = OP_0 (pushes empty bytes → falsy top-of-stack)
        let se = trace_error_test("00", VERIFY_ALL_PRE_TAPROOT);
        assert_eq!(se, Some(ScriptExecError::EvalFalse));
    }

    #[test]
    fn test_script_error_equal_verify() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // scriptPubKey: OP_1 OP_2 OP_EQUALVERIFY (1 ≠ 2 → EqualVerify)
        let se = trace_error_test("515288", VERIFY_ALL_PRE_TAPROOT);
        assert_eq!(se, Some(ScriptExecError::EqualVerify));
    }

    #[test]
    fn test_debugger_drop_unregisters() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Create and drop a debugger
        {
            let debugger = ScriptDebugger::new();
            drop(debugger);
        }

        // Should be able to create another one
        {
            let debugger = ScriptDebugger::new();
            drop(debugger);
        }
    }

    #[test]
    fn test_double_debugger_panics() {
        let _ = testing_setup();
        // Use unwrap_or_else to handle a potentially poisoned mutex from a prior panic
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let result = std::panic::catch_unwind(|| {
            let _debugger1 = ScriptDebugger::new();
            let _debugger2 = ScriptDebugger::new();
        });

        assert!(result.is_err(), "Expected panic from double debugger registration");
        let err = result.unwrap_err();
        let msg = err.downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(msg.contains("ScriptDebugger is already active"), "Unexpected panic message: {}", msg);
    }

    /// Minimal legacy transaction with a 1-byte scriptSig.
    /// null prevout (32-byte zero txid, index 0xffffffff), 1 output of 0 sat.
    ///
    /// Layout: version(4) | 1 input | txid(32) | vout(4) | scriptSig_len(1) | scriptSig(1) |
    ///         sequence(4) | 1 output | value(8) | scriptPubKey_len(1) | scriptPubKey(1) | locktime(4)
    fn minimal_tx_hex(scriptsig_byte: u8) -> String {
        // Null prevout coinbase-like input, useful for testing EvalScript in isolation.
        format!(
            "01000000\
             01\
             0000000000000000000000000000000000000000000000000000000000000000\
             00000000\
             01{:02x}\
             ffffffff\
             01\
             0000000000000000\
             01\
             51\
             00000000",
            scriptsig_byte
        )
    }

    /// Helper: collect only the ScriptPubKey-phase steps that carry an instruction.
    fn spk_ops(trace: &bitcoinkernel::ScriptTrace) -> Vec<&bitcoinkernel::ScriptStep> {
        trace
            .iter()
            .filter(|s| s.phase == ScriptPhase::ScriptPubKey && s.instruction.is_some())
            .collect()
    }

    // ── OP_IF / f_exec tests ────────────────────────────────────────────────

    /// scriptSig = OP_1 (truthy) → OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
    ///
    /// IF branch is taken, so OP_2 executes (f_exec=true) and OP_3 is skipped
    /// (f_exec=false).  OP_ELSE fires while still in the executing IF branch
    /// (f_exec=true); OP_ENDIF fires while in the false ELSE branch (f_exec=false,
    /// because DEBUG_SCRIPT fires at the top of the loop, before the pop).
    #[test]
    fn test_f_exec_if_branch_taken() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // OP_IF=0x63  OP_2=0x52  OP_ELSE=0x67  OP_3=0x53  OP_ENDIF=0x68
        let spk_hex = "6352675368";
        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(spk_hex).unwrap().as_slice()).unwrap();
        let tx = Transaction::new(
            hex::decode(minimal_tx_hex(0x51)).unwrap().as_slice(), // 0x51 = OP_1
        )
        .unwrap();
        let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

        let trace = trace_verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );

        assert!(trace.success, "OP_IF with true condition should succeed");

        let ops = spk_ops(&trace);
        assert_eq!(
            ops.len(),
            5,
            "Expected 5 ops: OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF"
        );

        // OP_IF: outer context is executing
        assert_eq!(ops[0].instruction.as_ref().unwrap().opcode, Opcode::OpIf);
        assert!(ops[0].f_exec, "OP_IF should fire in executing context");

        // OP_2: inside the true IF branch → executes
        assert_eq!(ops[1].instruction.as_ref().unwrap().opcode, Opcode::OpNum(2));
        assert!(ops[1].f_exec, "OP_2 in true IF branch should execute");

        // OP_ELSE: fires while still in the executing IF branch (before the toggle)
        assert_eq!(ops[2].instruction.as_ref().unwrap().opcode, Opcode::OpElse);
        assert!(ops[2].f_exec, "OP_ELSE fires while IF branch is executing");

        // OP_3: inside the false ELSE branch → skipped
        assert_eq!(ops[3].instruction.as_ref().unwrap().opcode, Opcode::OpNum(3));
        assert!(!ops[3].f_exec, "OP_3 in false ELSE branch should be skipped");

        // OP_ENDIF: fires while still in the false ELSE context (before the pop)
        assert_eq!(ops[4].instruction.as_ref().unwrap().opcode, Opcode::OpEndIf);
        assert!(
            !ops[4].f_exec,
            "OP_ENDIF fires before the false ELSE branch is popped"
        );
    }

    /// scriptSig = OP_0 (falsy) → OP_IF OP_2 OP_ELSE OP_1 OP_ENDIF
    ///
    /// ELSE branch is taken, so OP_2 is skipped (f_exec=false) and OP_1
    /// executes (f_exec=true).  OP_ELSE fires while still in the false IF branch
    /// (f_exec=false); OP_ENDIF fires while in the true ELSE branch (f_exec=true).
    #[test]
    fn test_f_exec_else_branch_taken() {
        let _ = testing_setup();
        let _lock = DEBUGGER_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // OP_IF=0x63  OP_2=0x52  OP_ELSE=0x67  OP_1=0x51  OP_ENDIF=0x68
        let spk_hex = "6352675168";
        let script_pubkey =
            ScriptPubkey::try_from(hex::decode(spk_hex).unwrap().as_slice()).unwrap();
        let tx = Transaction::new(
            hex::decode(minimal_tx_hex(0x00)).unwrap().as_slice(), // 0x00 = OP_0 → falsy
        )
        .unwrap();
        let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();

        let trace = trace_verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );

        assert!(
            trace.success,
            "OP_IF with false condition (ELSE branch) should succeed"
        );

        let ops = spk_ops(&trace);
        assert_eq!(
            ops.len(),
            5,
            "Expected 5 ops: OP_IF OP_2 OP_ELSE OP_1 OP_ENDIF"
        );

        // OP_IF: outer context is executing
        assert_eq!(ops[0].instruction.as_ref().unwrap().opcode, Opcode::OpIf);
        assert!(ops[0].f_exec, "OP_IF should fire in executing context");

        // OP_2: inside the false IF branch → skipped
        assert_eq!(ops[1].instruction.as_ref().unwrap().opcode, Opcode::OpNum(2));
        assert!(!ops[1].f_exec, "OP_2 in false IF branch should be skipped");

        // OP_ELSE: fires while still in the false IF branch (before the toggle)
        assert_eq!(ops[2].instruction.as_ref().unwrap().opcode, Opcode::OpElse);
        assert!(
            !ops[2].f_exec,
            "OP_ELSE fires while IF branch is false (before toggle)"
        );

        // OP_1: inside the true ELSE branch → executes
        assert_eq!(ops[3].instruction.as_ref().unwrap().opcode, Opcode::OpNum(1));
        assert!(ops[3].f_exec, "OP_1 in true ELSE branch should execute");

        // OP_ENDIF: fires while in the true ELSE branch (before the pop)
        assert_eq!(ops[4].instruction.as_ref().unwrap().opcode, Opcode::OpEndIf);
        assert!(
            ops[4].f_exec,
            "OP_ENDIF fires before the true ELSE branch is popped"
        );
    }
}
