#[allow(unused_use)]
#[test_only]
module atomic_swapv1::AtomicSwapTests {
    use sui::test_scenario::{Self as ts, Scenario};
    use sui::coin::{Self, Coin};
    use sui::sui::{Self, SUI};
    use sui::clock::{Self, Clock};
    use 0x1::hash as hash_lib;
    use sui::hash::blake2b256;
    use atomic_swapv1::AtomicSwap::{Self, OrdersRegistry};
    use sui::address;
    // use atomic_swapv1::AtomicSwap::EINCORRECT_FUNDS;

    // Test addresses
    const ADMIN: address = @0xAD;
    const INITIATOR: address = @0xA1;
    const REDEEMER: address = @0xA2;
    
    // Test constants
    const SWAP_AMOUNT: u256 = 1000;
    const TIMELOCK: u256 = 3600000; // 1 hour in milliseconds
    
    // Setup function that creates a test environment
    fun setup(): Scenario {
        let mut scenario = ts::begin(ADMIN);
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            // Create registry for SUI coins
            let _registry_id = AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
        };
        
        scenario
    }
    
    // Helper to create test coins
    fun mint_coins(amount: u256, ctx: &mut tx_context::TxContext): Coin<SUI> {
        coin::mint_for_testing<SUI>(amount as u64, ctx)
    }
    
    // Helper to generate a test secret and hash
    fun generate_secret(): (vector<u8>, vector<u8>) {
        let secret = b"thisisasecretphrase12345";
        let secret_hash = hash_lib::sha2_256(secret);
        (secret, secret_hash)
    }
    
    // Helper to generate mock ED25519 keypair
    
    fun generate_keypair(): (vector<u8>, address, vector<u8>, address){
        
        let _initiator_sk = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
        let initiator_pk = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";

        let _redeemer_sk = x"c5e26f9b31288c268c31217de8d2a783eec7647c2b8de48286f0a25a2dd6594b";
        let redeemer_pk = x"f1a756ceb2955f680ab622c9c271aa437a22aa978c34ae456f24400d6ea7ccdd";

        let initiator_address = generate_address(initiator_pk);
        let redeemer_address = generate_address(redeemer_pk);

        (initiator_pk, initiator_address, redeemer_pk, redeemer_address)
    }

    fun generate_address(pubk: vector<u8>) : address {
        let flag: u8 = 0; // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
        let mut preimage = vector::empty<u8>();
        vector::push_back(&mut preimage, flag);
        vector::append(&mut preimage, pubk);
        let add = blake2b256(&preimage);
        let address = address::from_bytes(add);
        address
    }
    // Common initialization function for tests
    fun initialize_test_swap(
        scenario: &mut Scenario, 
        clock: &Clock,
        initiator_address: address,
        redeemer_pubk: vector<u8>,
        amount: u256,
        timelock: u256
    ): vector<u8> {
        let (_, secret_hash) = generate_secret();
        // std::debug::print(&redeemer_pk);
        // std::debug::print(&redeemer_address);
        // Mint coins to the initiator
        ts::next_tx(scenario, ADMIN);
        {
            let mint_coins = mint_coins(amount, ts::ctx(scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Initialize swap
        ts::next_tx(scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(scenario);
            
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pubk,
                secret_hash,
                amount,
                timelock,
                init_coins,
                clock,
                ts::ctx(scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Return order ID for further operations
        AtomicSwap::generate_order_id(secret_hash, initiator_address, timelock, generate_address(redeemer_pubk))
    }

    // Test registry creation
    #[test]
    fun test_create_registry() {
        let mut scenario = setup();
        
        ts::next_tx(&mut scenario, ADMIN);
        {
            let registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            // Just verify we can take the shared registry
            ts::return_shared(registry);
        };
        
        ts::end(scenario);
    }
    
    // Test successful swap initiation
    #[test]
    fun test_init_swap() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate test data
        let (_, secret_hash) = generate_secret();
        let (__initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        
        // Mint coins to the initiator
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Initiate a swap
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pk,
                secret_hash,
                SWAP_AMOUNT,
                TIMELOCK,
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            // Generate order ID to verify the order was created
            // let order_id = AtomicSwap::generate_order_id(secret_hash, INITIATOR, TIMELOCK, generate_address(redeemer_pk));
            // let order = AtomicSwap::get_order(&registry, order_id);
            
            // // Verify the order details
            // assert!(order.initiator == INITIATOR, 0);
            // assert!(order.redeemer == REDEEMER, 0);
            // assert!(order.amount == SWAP_AMOUNT, 0);
            // assert!(order.is_fulfilled == false, 0);
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test successful redemption
    #[test]
    fun test_redeem_swap() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));

        let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        
        // Generate secret for redemption
        let (secret, _) = generate_secret();
        
        // Now redeem the swap
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            ts::return_shared(registry);
        };

        ts::next_tx(&mut scenario, redeemer_address);
        {
            // Check that REDEEMER received the coins
            let redeemed_bal = ts::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&redeemed_bal) == SWAP_AMOUNT as u64, 0);
            ts::return_to_sender<Coin<SUI>>(&scenario, redeemed_bal);
        };

        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test successful refund after timelock expires
    #[test]
    fun test_refund_swap() {
        let mut scenario = setup();
        let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        
        // Advance time past timelock
        ts::next_tx(&mut scenario, ADMIN);
        {
            // Advance clock past timelock
            clock::increment_for_testing(&mut clock, (TIMELOCK + 1000) as u64);
        };
        
        // Now refund the swap
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::refund_swap(
                &mut registry,
                order_id,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        ts::next_tx(&mut scenario, initiator_address);
        {
            // Check that INITIATOR received the coins back
            let refunded_bal = ts::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&refunded_bal) as u256 == SWAP_AMOUNT, 0);
            ts::return_to_sender<Coin<SUI>>(&scenario, refunded_bal);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to redeem with incorrect secret
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EINCORRECT_SECRET)]
    fun test_revert_redeem_with_incorrect_secret() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Initialize a swap
        let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);

        // Try to redeem with incorrect secret
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // Use wrong secret
            let wrong_secret = b"wrongsecretphrase";
            
            // This should fail due to incorrect secret
            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                wrong_secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to refund before timelock expires
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_NOT_EXPIRED)]
    fun test_revert_refund_before_timelock() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        // Try to refund before timelock expires (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // This should fail since timelock hasn't expired
            AtomicSwap::refund_swap(
                &mut registry,
                order_id,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test duplicate order creation
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EDUPLICATE_ORDER)]
    fun test_revert_init_duplicate_order() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        // Initialize a swap
        let _order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        // Try to create a duplicate with same secret and initiator
        let (_, secret_hash) = generate_secret();
        
        // Mint more coins for the second attempt
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Try to create a duplicate (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            // This should fail due to duplicate order_id
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pk,
                secret_hash,
                SWAP_AMOUNT,
                TIMELOCK,
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to redeem an already fulfilled order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_FULFILLED)]
    fun test_revert_redeem_already_fulfilled() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);

        // Generate secret for redemption
        let (secret, _) = generate_secret();
        
        // First redeem successfully
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Try to redeem again (should fail)
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // This should fail since the order is already fulfilled
            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test that same initiator and redeemer is rejected
    #[test]
    #[expected_failure(abort_code = AtomicSwap::ESAME_INITIATOR_REDEEMER)]
    fun test_revert_init_same_initiator_redeemer() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate test data
        let (_, secret_hash) = generate_secret();
        let (initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();
        
        // Mint coins to the initiator
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Try to create a swap with same initiator and redeemer (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            // This should fail since initiator and redeemer are the same
            AtomicSwap::initiate(
                &mut registry,
                initiator_pk,
                secret_hash,
                SWAP_AMOUNT,
                TIMELOCK,
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to refund an already fulfilled order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_FULFILLED)]
    fun test_revert_refund_already_fulfilled() {
        let mut scenario = setup();
        let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);

        // Generate secret for redemption
        let (secret, _) = generate_secret();
        
        // First redeem successfully
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Advance time past timelock
        ts::next_tx(&mut scenario, ADMIN);
        {
            // Advance clock past timelock
            clock::increment_for_testing(&mut clock, (TIMELOCK + 1000) as u64);
        };
        
        // Try to refund after redemption (should fail)
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // This should fail since the order is already fulfilled
            AtomicSwap::refund_swap(
                &mut registry,
                order_id,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test zero timelock
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EZERO_TIMELOCK)]
    fun test_revert_init_zero_timelock() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate test data
        let (_, secret_hash) = generate_secret();
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        
        // Mint coins to the initiator
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Try to create a swap with zero timelock (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            // This should fail due to zero timelock
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pk,
                secret_hash,
                SWAP_AMOUNT,
                0, // Zero timelock
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test zero amount
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EZERO_AMOUNT)]
    fun test_revert_init_swap_zero_amount() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate test data
        let (_, secret_hash) = generate_secret();
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        
        // Mint coins to the initiator
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Try to create a swap with zero amount (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            // This should fail due to zero amount
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pk,
                secret_hash,
                0, // Zero amount
                TIMELOCK,
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test insufficient balance
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EINCORRECT_FUNDS)]
    fun test_revert_init_swap_insufficient_balance() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate test data
        let (_, secret_hash) = generate_secret();
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        // Mint coins to the initiator (less than swap amount)
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mint_coins = mint_coins(SWAP_AMOUNT / 2, ts::ctx(&mut scenario));
            transfer::public_transfer(mint_coins, initiator_address);
        };
        
        // Try to create a swap with insufficient balance (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            
            // This should fail due to insufficient balance
            AtomicSwap::initiate(
                &mut registry,
                redeemer_pk,
                secret_hash,
                SWAP_AMOUNT, // Amount greater than available coins
                TIMELOCK,
                init_coins,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to redeem non-existent order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_NOT_INITIATED)]
    fun test_revert_redeem_nonexistent_order() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Create a fake order ID
        let fake_order_id = b"non_existent_order_id";
        let (secret, _) = generate_secret();
        
        // Try to redeem a non-existent order (should fail)
        ts::next_tx(&mut scenario, REDEEMER);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // This should fail since the order doesn't exist
            AtomicSwap::redeem_swap(
                &mut registry,
                fake_order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
    
    // Test attempting to refund non-existent order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_NOT_INITIATED)]
    fun test_revert_refund_nonexistent_order() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Create a fake order ID
        let fake_order_id = b"non_existent_order_id";
        
        // Try to refund a non-existent order (should fail)
        ts::next_tx(&mut scenario, INITIATOR);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            // This should fail since the order doesn't exist
            AtomicSwap::refund_swap(
                &mut registry,
                fake_order_id,
                &clock,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }

    // Test successful instant refund
    #[test]
    fun test_instant_refund() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        // Initialize a swap
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        // std::debug::print(&order_id);
        
        // Generate using fastcrypto-cli
        let refund_signature = x"b75b24e38dd9e736a45c1d0351b17babe0020c45f09ff8e2832a2276bec818b21a9e7969f3986c0735b707d1a59af75e694196f3d33b3174879e973fb04ef30e";
        
        // Perform instant refund
        ts::next_tx(&mut scenario, ADMIN);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
            let registry_addr = object::uid_to_address(reg_id);
            let refund_digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);
            std::debug::print(&refund_digest);
            
            AtomicSwap::instant_refund(
                &mut registry,
                order_id,
                refund_signature,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Check that initiator received the coins back
        ts::next_tx(&mut scenario, initiator_address);
        {
            let refunded_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
            assert!(coin::value(&refunded_coins) as u256 == SWAP_AMOUNT, 0);
            ts::return_to_sender(&scenario, refunded_coins);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }

    // Test invalid signature for instant refund
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EINVALID_SIGNATURE)]
    fun test_revert_instant_refund_invalid_signature() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();
        
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);

        // Generate an invalid refund signature
        let invalid_refund_signature = x"0fc727690a97bb47058e36156646f0129977697607b7d8bc605bcd3e516d14280b841cfea6a5ee72863604de5602c8e1ad75c4fb7efb2e7d2e2b5f7658b46e0e";
        
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::instant_refund(
                &mut registry,
                order_id,
                invalid_refund_signature,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }

    // Test instant refund on already fulfilled order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_FULFILLED)]
    fun test_revert_instant_refund_already_fulfilled() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();
        
        let order_id = initialize_test_swap(&mut scenario, &clock, initiator_address, redeemer_pk, SWAP_AMOUNT, TIMELOCK);
        
        // Generate secret for redemption
        let (secret, _) = generate_secret();
        
        // First redeem successfully
        ts::next_tx(&mut scenario, redeemer_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::redeem_swap(
                &mut registry,
                order_id,
                secret,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        // Generate the refund signature
        let refund_signature = x"bb814078fd2dfbe03cdde1e83dcd93b54b35a33781cf1bb4c1c1209c1954fa025ce2e129945cbf1ac12ad1e4b8a6ce082771387370c15151df4f704c3ed82f0e";
        
        // Try to perform instant refund on already fulfilled order (should fail)
        ts::next_tx(&mut scenario, initiator_address);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::instant_refund(
                &mut registry,
                order_id,
                refund_signature,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }

    // Test instant refund on non-existent order
    #[test]
    #[expected_failure(abort_code = AtomicSwap::EORDER_NOT_INITIATED)]
    fun test_revert_instant_refund_nonexistent_order() {
        let mut scenario = setup();
        let clock = clock::create_for_testing(ts::ctx(&mut scenario));
        
        // Generate fake order ID
        let fake_order_id = b"non_existent_order_id";
        
        // Generate the refund signature
        let refund_signature = x"bb814078fd2dfbe03cdde1e83dcd93b54b35a33781cf1bb4c1c1209c1954fa025ce2e129945cbf1ac12ad1e4b8a6ce082771387370c15151df4f704c3ed82f0e";
        
        // Try to perform instant refund on non-existent order (should fail)
        ts::next_tx(&mut scenario, INITIATOR);
        {
            let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
            
            AtomicSwap::instant_refund(
                &mut registry,
                fake_order_id,
                refund_signature,
                ts::ctx(&mut scenario)
            );
            
            ts::return_shared(registry);
        };
        
        clock::destroy_for_testing(clock);
        ts::end(scenario);
    }
}