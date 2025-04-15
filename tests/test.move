module atomic_swapv1::tests {
    #[test_only]
    use sui::test_scenario;
    use bridge::crypto;
    use sui::sui::SUI;
    use sui::coin::{Self, Coin};
    use sui::clock::{Self, Clock};
    use sui::transfer;
    use sui::event;
    use sui::object::{Self, ID, UID};
    use sui::table::{Self, Table};
    use sui::hash::{keccak256, blake2b256};
    use sui::address;
    use sui::ecdsa_k1;
    use sui::ed25519;
    use sui::object_table::{Self, ObjectTable};
    use sui::tx_context::{Self, TxContext};
    use sui::bcs;
    use std::vector;
    use 0x1::hash;
    use atomic_swapv1::AtomicSwap::{Order, OrdersRegistry, create_orders_registry, initialize_Swap, initiate_with_sig, initiate_digest, instant_refund_digest, generate_order_id, get_initiate_typehash, get_order, get_refund_typehash, redeem_Swap, refund_Swap, Redeemed, Initiated, Refunded};

    // ============== Test Constants ==============
    #[test_only]
    const TEST_AMOUNT: u64 = 100;
    
    #[test_only]
    const TEST_TIMELOCK: u64 = 3600000; // 1 hour in milliseconds
    
    #[test_only]
    const INITIATOR_ADDRESS: address = @0xa11ce;
    
    #[test_only]
    const REDEEMER_ADDRESS: address = @0xb0b;
    
    #[test_only]
    const TEST_SECRET: vector<u8> = b"ABAB";

    // ============== Test Helpers ==============
    
    #[test_only]
    /// Sets up the basic test environment and returns required objects
    fun setup_test_env(ctx: &mut TxContext): (Clock, ID) {
        let clock = clock::create_for_testing(ctx);
        let registry_id = create_orders_registry<SUI>(ctx);
        (clock, registry_id)
    }
    
    #[test_only]
    /// Mints and transfers test coins to the given address
    fun setup_test_coins(recipient: address, amount: u64, scenario: &mut test_scenario::Scenario) {
        test_scenario::next_tx(scenario, recipient);
        {
            let coins = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins, recipient);
        };
    }
    
    #[test_only]
    /// Creates and initializes a test order
    fun create_order(
        scenario: &mut test_scenario::Scenario,
        initiator: address,
        redeemer: address, 
        redeemer_pk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64,
        timelock: u64,
        clock: &mut Clock,
        timestamp: u64
    ) {
        test_scenario::next_tx(scenario, initiator);
        
        let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
        let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
        
        // Set the clock to the specified timestamp
        clock::set_for_testing(clock, timestamp);
        
        initialize_Swap<SUI>(
            &mut orders_reg,
            redeemer, 
            redeemer_pk,
            secret_hash,
            amount,
            timelock,
            coins,
            clock,
            test_scenario::ctx(scenario)
        );
        
        test_scenario::return_shared(orders_reg);
    }
    #[test_only]
    /// Creates and initializes a test order
    fun create_order_reg<CoinType>(
        scenario: &mut test_scenario::Scenario,
    ): vector<u8> {
        let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
        let scenario = &mut scenario_val;
        let registry_id: vector<u8>;
        test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
        {
            registry_id = create_orders_registry<SUI>(test_scenario::ctx(scenario));
            
            // Next transaction to verify the registry
            test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
            {
                let registry = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
                assert!(object_table::is_empty(&registry.orders), 0);
                assert!(object::uid_to_inner(&registry.id) == registry_id, 0);
                test_scenario::return_shared(registry);
            };
        };
        
        test_scenario::end(scenario_val);
        registry_id;
    }
    
    #[test_only]
    /// Validates an order in the registry
    fun validate_order_state(
        scenario: &mut test_scenario::Scenario, 
        order_id: vector<u8>,
        expected_initiator: address,
        expected_redeemer: address,
        expected_amount: u64,
        expected_timelock: u64,
        expected_secret_hash: vector<u8>,
        expected_fulfilled: bool
    ) {
        test_scenario::next_tx(scenario, expected_initiator);
        
        let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
        
        // Ensure the order exists
        assert!(object_table::contains(&orders_reg.orders, order_id), ECREATED_SWAP_NOT_OURS);
        
        // Validate order state
        let order = object_table::borrow(&orders_reg.orders, order_id);
        assert!(order.initiator == expected_initiator, ECREATED_SWAP_NOT_OURS);
        assert!(order.redeemer == expected_redeemer, ECREATED_SWAP_NOT_OURS);
        assert!(coin::value(&order.coins) == expected_amount, ECREATED_SWAP_NOT_OURS);
        assert!(order.timelock == expected_timelock, ECREATED_SWAP_NOT_OURS);
        assert!(order.is_fulfilled == expected_fulfilled, 0);
        
        test_scenario::return_shared(orders_reg);
    }
    
    #[test_only]
    /// Helper to attempt a refund with expected result
    fun try_refund(
        scenario: &mut test_scenario::Scenario,
        order_id: vector<u8>,
        refunder: address,
        clock: &Clock,
        should_succeed: bool,
        expected_error: u64
    ) {
        test_scenario::next_tx(scenario, refunder);
        
        let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
        
        if (should_succeed) {
            refund_Swap<SUI>(
                &mut orders_reg,
                order_id,
                clock,
                test_scenario::ctx(scenario)
            );
        } else {
            // Use test_utils to expect a specific abort code
            test_utils::assert_abort_with(
                || {
                    refund_Swap<SUI>(
                        &mut orders_reg,
                        order_id,
                        clock,
                        test_scenario::ctx(scenario)
                    );
                },
                expected_error
            );
        };
        
        test_scenario::return_shared(orders_reg);
    }
    
    #[test_only]
    /// Helper to attempt a redeem with expected result
    fun try_redeem(
        scenario: &mut test_scenario::Scenario,
        order_id: vector<u8>,
        redeemer: address,
        secret: vector<u8>,
        clock: &Clock,
        should_succeed: bool,
        expected_error: u64
    ) {
        test_scenario::next_tx(scenario, redeemer);
        
        let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
        
        if (should_succeed) {
            redeem_Swap<SUI>(
                &mut orders_reg,
                order_id,
                secret,
                clock,
                test_scenario::ctx(scenario)
            );
        } else {
            test_utils::assert_abort_with(
                || {
                    redeem_Swap<SUI>(
                        &mut orders_reg,
                        order_id,
                        secret,
                        clock,
                        test_scenario::ctx(scenario)
                    );
                },
                expected_error
            );
        };
        
        test_scenario::return_shared(orders_reg);
    }
    
    #[test_only]
    /// Helper to check if coins were received by an address
    fun verify_coin_receipt(
        scenario: &mut test_scenario::Scenario,
        recipient: address,
        expected_amount: u64
    ) {
        test_scenario::next_tx(scenario, recipient);
        
        // Check that recipient received coins
        let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
        assert!(coin::value(&coins) == expected_amount, 0);
        
        // Return the coins
        test_scenario::return_to_sender(scenario, coins);
    }

    // ============== Main Test Cases ==============
    
    #[test]
    /// Test creating an orders registry
    public fun test_create_orders_registry() {
        let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
        let scenario = &mut scenario_val;
        
        test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
        {
            let registry_id = create_orders_registry<SUI>(test_scenario::ctx(scenario));
            
            // Next transaction to verify the registry
            test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
            {
                let registry = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
                assert!(object_table::is_empty(&registry.orders), 0);
                assert!(object::uid_to_inner(&registry.id) == registry_id, 0);
                test_scenario::return_shared(registry);
            };
        };
        
        test_scenario::end(scenario_val);
    }
    
    // #[test]
    // /// Test the happy path of initializing a swap
    // public fun test_initialize_swap() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         0 // Initial timestamp
    //     );
        
    //     // Validate the created order
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         false // Not fulfilled
    //     );
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test the refund flow (happy path)
    // public fun test_refund_swap() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
    //     let initial_timestamp = 0;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // Advance clock beyond timelock and refund
    //     clock::set_for_testing(&mut clock, initial_timestamp + TEST_TIMELOCK + 1000);
    //     try_refund(scenario, order_id, INITIATOR_ADDRESS, &clock, true, 0);
        
    //     // Verify order is marked fulfilled
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         true // Now fulfilled
    //     );
        
    //     // Verify initiator received funds
    //     verify_coin_receipt(scenario, INITIATOR_ADDRESS, TEST_AMOUNT);
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test the redeem flow (happy path)
    // public fun test_redeem_swap() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
    //     let initial_timestamp = 0;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // Set time before expiry and redeem
    //     clock::set_for_testing(&mut clock, initial_timestamp + TEST_TIMELOCK - 1000);
    //     try_redeem(scenario, order_id, REDEEMER_ADDRESS, TEST_SECRET, &clock, true, 0);
        
    //     // Verify order is marked fulfilled
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         true // Now fulfilled
    //     );
        
    //     // Verify redeemer received funds
    //     verify_coin_receipt(scenario, REDEEMER_ADDRESS, TEST_AMOUNT);
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // // ============== Error Test Cases ==============
    
    // #[test]
    // /// Test attempting to refund before timelock expires
    // public fun test_refund_before_timelock() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
    //     let initial_timestamp = 0;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // Set time before expiry and attempt refund (should fail)
    //     clock::set_for_testing(&mut clock, initial_timestamp + TEST_TIMELOCK - 1000);
    //     try_refund(scenario, order_id, INITIATOR_ADDRESS, &clock, false, EORDER_NOT_EXPIRED);
        
    //     // Verify order is still not fulfilled
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         false // Still not fulfilled
    //     );
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test redeeming with incorrect secret
    // public fun test_redeem_with_incorrect_secret() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
    //     let initial_timestamp = 0;
    //     let wrong_secret = b"WRONG";
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // Try to redeem with wrong secret
    //     try_redeem(scenario, order_id, REDEEMER_ADDRESS, wrong_secret, &clock, false, ESECRET_MISMATCH);
        
    //     // Verify order is still not fulfilled
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         false // Still not fulfilled
    //     );
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }

    // #[test]
    // /// Test instant refund with signature verification
    // public fun test_instant_refund() {
    //     // Create a test keypair for the redeemer
    //     let redeemer_sk = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
    //     let redeemer_pk = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
        
    //     // Derive redeemer address from public key
    //     let flag: u8 = 0;
    //     let mut preimage = vector::empty<u8>();
    //     vector::push_back(&mut preimage, flag);
    //     vector::append(&mut preimage, redeemer_pk);
    //     let redeemer_add = blake2b256(&preimage);
    //     let redeemer_address = address::from_bytes(redeemer_add);
        
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let initial_timestamp = 0;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap with the derived redeemer address
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         redeemer_address,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // Calculate refund digest and use pre-computed signature
    //     let refund_digest = instant_refund_digest(order_id);
    //     let signature = x"efc727690a97bb47058e36156646f0129977697607b7d8bc605bcd3e516d14280b841cfea6a5ee72863604de5602c8e1ad75c4fb7efb2e7d2e2b5f7658b46e0e";
        
    //     // Execute instant refund
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     {
    //         let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
    //         instant_refund<SUI>(
    //             &mut orders_reg,
    //             order_id,
    //             signature,
    //             &clock,
    //             test_scenario::ctx(scenario)
    //         );
            
    //         test_scenario::return_shared(orders_reg);
    //     };
        
    //     // Verify order is marked fulfilled
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         INITIATOR_ADDRESS,
    //         redeemer_address,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         true // Now fulfilled
    //     );
        
    //     // Verify initiator received funds
    //     verify_coin_receipt(scenario, INITIATOR_ADDRESS, TEST_AMOUNT);
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test trying to refund an already fulfilled order
    // public fun test_refund_fulfilled_order() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
    //     let initial_timestamp = 0;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Initialize swap
    //     let order_id = create_order(
    //         scenario,
    //         INITIATOR_ADDRESS,
    //         REDEEMER_ADDRESS,
    //         redeemer_pk,
    //         secret_hash,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         &mut clock,
    //         initial_timestamp
    //     );
        
    //     // First redeem successfully
    //     clock::set_for_testing(&mut clock, initial_timestamp + TEST_TIMELOCK - 1000);
    //     try_redeem(scenario, order_id, REDEEMER_ADDRESS, TEST_SECRET, &clock, true, 0);
        
    //     // Then try to refund (should fail)
    //     clock::set_for_testing(&mut clock, initial_timestamp + TEST_TIMELOCK + 1000);
    //     try_refund(scenario, order_id, INITIATOR_ADDRESS, &clock, false, EORDER_FULFILLED);
        
    //     // Verify redeemer received funds
    //     verify_coin_receipt(scenario, REDEEMER_ADDRESS, TEST_AMOUNT);
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test initialization with insufficient balance
    // public fun test_initialize_insufficient_balance() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup coins with LESS than required amount
    //     let insufficient_amount = TEST_AMOUNT - 1;
    //     setup_test_coins(INITIATOR_ADDRESS, insufficient_amount, scenario);
        
    //     // Try to initialize with insufficient funds
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     {
    //         let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
    //         let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
            
    //         test_utils::assert_abort_with(
    //             || {
    //                 initialize_Swap<SUI>(
    //                     &mut orders_reg,
    //                     REDEEMER_ADDRESS, 
    //                     redeemer_pk,
    //                     secret_hash,
    //                     TEST_AMOUNT, // Requesting more than available
    //                     TEST_TIMELOCK,
    //                     coins,
    //                     &clock,
    //                     test_scenario::ctx(scenario)
    //                 );
    //             },
    //             EINSUFFICIENT_BALANCE
    //         );
            
    //         test_scenario::return_to_sender(scenario, coins);
    //         test_scenario::return_shared(orders_reg);
    //     };
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }

    // #[test]
    // /// Test attempting to initialize a swap with same initiator and redeemer
    // public fun test_initialize_same_addresses() {
    //     // Setup
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let mut scenario_val = test_scenario::begin(INITIATOR_ADDRESS);
    //     let scenario = &mut scenario_val;
    //     let redeemer_pk = x"00"; // Dummy PK for testing
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     let (mut clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(INITIATOR_ADDRESS, TEST_AMOUNT, scenario);
        
    //     // Try to initialize with same address for initiator and redeemer
    //     test_scenario::next_tx(scenario, INITIATOR_ADDRESS);
    //     {
    //         let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
    //         let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
            
    //         test_utils::assert_abort_with(
    //             || {
    //                 initialize_Swap<SUI>(
    //                     &mut orders_reg,
    //                     INITIATOR_ADDRESS, // Same as initiator
    //                     redeemer_pk,
    //                     secret_hash,
    //                     TEST_AMOUNT,
    //                     TEST_TIMELOCK,
    //                     coins,
    //                     &clock,
    //                     test_scenario::ctx(scenario)
    //                 );
    //             },
    //             ESAME_INITIATOR_REDEEMER
    //         );
            
    //         test_scenario::return_to_sender(scenario, coins);
    //         test_scenario::return_shared(orders_reg);
    //     };
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
    
    // #[test]
    // /// Test initialization with signature
    // public fun test_initialize_with_signature() {
    //     // Setup keypair for initiator
    //     let initiator_sk = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
    //     let initiator_pk = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
        
    //     // Derive initiator address
    //     let flag: u8 = 0;
    //     let mut preimage = vector::empty<u8>();
    //     vector::push_back(&mut preimage, flag);
    //     vector::append(&mut preimage, initiator_pk);
    //     let initiator_add = blake2b256(&preimage);
    //     let initiator_address = address::from_bytes(initiator_add);
        
    //     // Test values
    //     let redeemer_pk = x"123456"; // Dummy PK
    //     let secret_hash = hash::sha2_256(TEST_SECRET);
    //     let signature = x"3c671a57d6c991e06f735d29d9c24dc42b3a42064e80afec0423beea80d0597f2e1885699c1d89ce08bc5b26f4665d4fe3f4efd1de8e23fadf67970e6f9a7a00";
        
    //     // Setup test scenario
    //     let mut scenario_val = test_scenario::begin(initiator_address);
    //     let scenario = &mut scenario_val;
        
    //     // Create test environment
    //     test_scenario::next_tx(scenario, initiator_address);
    //     let (clock, _) = setup_test_env(test_scenario::ctx(scenario));
        
    //     // Setup test coins
    //     setup_test_coins(initiator_address, TEST_AMOUNT, scenario);
        
    //     // Execute initialization with signature
    //     let mut order_id: vector<u8>;
    //     test_scenario::next_tx(scenario, initiator_address);
    //     {
    //         let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
    //         let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
            
    //         order_id = initiate_with_sig<SUI>(
    //             &mut orders_reg,
    //             initiator_address,
    //             initiator_pk,
    //             REDEEMER_ADDRESS,
    //             redeemer_pk,
    //             signature,
    //             secret_hash,
    //             TEST_AMOUNT,
    //             TEST_TIMELOCK,
    //             coins,
    //             &clock,
    //             test_scenario::ctx(scenario)
    //         );
            
    //         test_scenario::return_shared(orders_reg);
    //     };
        
    //     // Verify order was created correctly
    //     validate_order_state(
    //         scenario,
    //         order_id,
    //         initiator_address,
    //         REDEEMER_ADDRESS,
    //         TEST_AMOUNT,
    //         TEST_TIMELOCK,
    //         secret_hash,
    //         false // Not fulfilled
    //     );
        
    //     // Cleanup
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
}