module atomic_swapv1::AtomicSwap {

    use sui::sui::{Self, SUI};                      // Sui tokens
    use sui::object::{Self, ID, UID};               // objects for the structs
    use sui::coin::{Self, Coin};                    // the coins
    use sui::tx_context::{Self, TxContext};         // Transaction Context
    use sui::clock::{Self, Clock};                  // To access time
    use sui::transfer;                              // To make the object publicly accessible
    use sui::event;                                 // To emit events
    use sui::table::{Self, Table};

    use 0x1::hash;                                  // To hash the secret, for the case of redeeming
    use sui::address;
    // Error codes, self-explanatory
    const ENOT_ENOUGH_BALANCE: u64 = 1;
    const ESWAP_EXPIRED: u64 = 2;
    const ESWAP_NOT_EXPIRED: u64 = 3;
    const ESECRET_MISMATCH: u64 = 4;
    const ECREATED_SWAP_NOT_OURS: u64 = 5;
    const ESWAP_ALREADY_REDEEMED_OR_REFUNDED: u64 = 6;

    // The Order struct
    public struct Order<phantom CoinType: drop> has key {
        id: UID,
        is_fulfilled: bool,
        initiator: address,
        redeemer: address,
        amount: u64,
        initiated_at: u64,
        coins: Coin<CoinType>,
        timelock: u64,
        secret_hash: vector<u8>
    }

    public struct OrdersRegistry has key, store {
        id: UID,
        orders: Table<vector<u8>, ID>
    }

    // --------------------------------------- Event Structs ---------------------------------------

    // Struct for the initialized Event
    public struct Initiated has copy, drop {
        order_id: ID,
        initiator: address,
        redeemer: address,
    }

    // Struct for the refund Event
    public struct Refunded has copy, drop {
        order_id: ID,
        initiator: address,
        redeemer: address,
    }

    // Struct for the redeem Event
    public struct Redeemed has copy, drop {
            order_id: ID,
            initiator: address,
            redeemer: address,
            secret: vector<u8>
    }

    fun init(ctx: &mut TxContext) {
            let orders_reg = OrdersRegistry {
                id: object::new(ctx),
                orders: table::new(ctx)
            };
            transfer::share_object(orders_reg);
        }

    fun create_orders_registry(ctx: &mut TxContext) {
        let orders_reg = OrdersRegistry {
            id: object::new(ctx),
            orders: table::new(ctx)
        };

        transfer::share_object(orders_reg);
    }

    public fun create_order_id(secret_hash: vector<u8>, initiator: address): vector<u8> {
        // Convert the address to a vector<u8> manually
        let mut address_bytes = vector::empty<u8>();
        let address_vec: vector<u8> = address::to_bytes(initiator); 
        vector::append(&mut address_bytes, address_vec);

        // Concatenate the secret_hash and address_bytes
        let mut data = vector::empty<u8>();
        vector::append(&mut data, secret_hash);
        vector::append(&mut data, address_bytes);

        // Compute the SHA256 hash of the concatenated data
        let hash_result: vector<u8> = hash::sha2_256(data);
        hash_result
    }
    // Creates a order object and makes it a shared_object
    public entry fun initialize_Swap<CoinType: drop>(
        orders_reg: &mut OrdersRegistry,
        redeemer: address,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Check that value of coins exceeds amount in order
        assert!(coin::value<CoinType>(&coins) >= amount, ENOT_ENOUGH_BALANCE);

        let id = object::new(ctx);
        let object_id = object::uid_to_inner(&id);
        let order_id = create_order_id(secret_hash, ctx.sender());

        // Check if the order_id already exists
        // assert!(!table::contains(&orders_reg.orders, order_id), EDUPLICATE_ORDER);

        // Emit event
        event::emit(Initiated {
            order_id: object_id,
            initiator: tx_context::sender(ctx),
            redeemer: redeemer
        });
        // get the required amount out of the users balance
        let order = Order {
            id: id,
            initiator: tx_context::sender(ctx),                                    // The address of the initiator 
            is_fulfilled: false,                                                             // Create a new ID for the object
            redeemer: redeemer,                                                 // The address of the redeemer
            amount: amount,
            secret_hash: secret_hash,                                           // The hashed secret
            initiated_at: clock::timestamp_ms(clock),                                                      // The amount to be transferred
            coins,                                                              // The coins where value(coins) == amount
            timelock       // THe expiry, being (timelock) hours away from initialization time
        };
        
        ////////////////
        // let obj_id = order.borrow_uid();
        ////////////////

        orders_reg.orders.add(order_id, object_id);
        // Share the object so anyone can access nad mutate it
        transfer::share_object<Order<CoinType>>(order);
    }

    // Refunds the coins and destroys Order object
    public entry fun refund_Swap<CoinType: drop>(
        order: &mut Order<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        // Makes sure that order has expired
        assert!(order.initiated_at + order.timelock < clock::timestamp_ms(clock), ESWAP_NOT_EXPIRED);
        assert!(order.is_fulfilled == false, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);
        // If coins are 0, then order has been used
        assert!(coin::value<CoinType>(&order.coins) > 0, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);
        // Unpack the Order object, only need initiator, coins and id (it cant be dropped) so the rest are all _ 
        let amount = order.amount;
        let initiator = order.initiator;
        order.is_fulfilled = true;

        // Emit event
        event::emit(Refunded {
            order_id: object::uid_to_inner(&order.id),
            initiator: order.initiator,
            redeemer: order.redeemer
        });

        // Transfer the coins to the initiator
        transfer::public_transfer(
            coin::split<CoinType>(
                &mut order.coins,
                amount,
                ctx
            ), 
            initiator
        );
    }

    // Redeems the coins and destroys the Order object
    public entry fun redeem_Swap<CoinType: drop>(
        order: &mut Order<CoinType>,
        orders_reg: &mut OrdersRegistry,
        secret: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        // Makes sure that order has not expired
        assert!(clock::timestamp_ms(clock) >= order.timelock + order.initiated_at, ESWAP_EXPIRED);

        // Ensure that the secret sent, after hashing, is same as the hashed_secret we have stored
        assert!(order.secret_hash == hash::sha2_256(secret), ESECRET_MISMATCH);

        let calc_order_id = create_order_id(secret, order.initiator);
        let calc_object_id = orders_reg.orders.borrow(calc_order_id);
        assert(calc_object_id == order.id.uid_to_inner(), 0);

        assert!(order.is_fulfilled == false, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);

        // Unpack the Order object, only need initiator, coins and id (it cant be dropped) so the rest are all _ 
        let amount = order.amount;
        let redeemer = order.redeemer;

        // If coins are 0, then order has been used
        assert!(coin::value<CoinType>(&order.coins) > 0, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);

        // Transfer the coins to the initiator
        transfer::public_transfer(
            coin::split<CoinType>(
                &mut order.coins,
                amount,
                ctx
            ), 
            redeemer
        );

        // Emit event
        event::emit(Redeemed {
            order_id: object::uid_to_inner(&order.id),
            initiator: order.initiator,
            redeemer: order.redeemer,
            secret: secret
        });
    }

    // ================================================= Tests ================================================= 

    #[test_only]
    use sui::test_scenario;     // The test scenario

    const EOBJECT_NOT_FOUND: u64 = 1;
    const ENOT_EMPTY: u64 = 2;
    
    #[test]
    public fun test_create_orders_registry() {
        let pub_address: address = @0xb0b;
        let mut scenario_val = test_scenario::begin(pub_address);
        let scenario = &mut scenario_val;

        test_scenario::next_tx(scenario, pub_address);
        {
            create_orders_registry(test_scenario::ctx(scenario));
        };

        // Next transaction to verify the registry
        test_scenario::next_tx(scenario, pub_address);
        {
            let registry = test_scenario::take_shared<OrdersRegistry>(scenario);
            assert!(table::is_empty(&registry.orders), ENOT_EMPTY);
            test_scenario::return_shared(registry);
        };

        scenario_val.end();
    }

    // Test just the initialization part of it
    #[test]
    public fun test_initialize_swap() {
        let initiator_address: address = @0xa11ce;     // Address of the initiator    
        let redeemer_address: address = @0xb0b;        // Address of the redeemer

        // The secrets
        let secret = b"ABAB";
        let secret_hash = hash::sha2_256(secret);

        let expiry: u64 = 1;  // 1 hour timelock
        let amount: u64 = 100;

        // Initializing the scenarios
        let mut scenario_val = test_scenario::begin(initiator_address);
        let scenario = &mut scenario_val;

        // Create a clock for testing
        let clock = clock::create_for_testing(test_scenario::ctx(scenario));

        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            create_orders_registry(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Initialize the order
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Call initialize_Swap
            initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address,
                secret_hash,
                amount, 
                expiry,
                coins,
                &clock,
                test_scenario::ctx(scenario)
            );

            // Return the modified registry
            test_scenario::return_shared(orders_reg);
        };

        // Verify the order
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the shared order
            let shared_swap = test_scenario::take_shared<Order<SUI>>(scenario);

            // Assertions
            assert!(shared_swap.initiator == initiator_address, ECREATED_SWAP_NOT_OURS);
            assert!(shared_swap.redeemer == redeemer_address, ECREATED_SWAP_NOT_OURS);
            assert!(coin::value<SUI>(&shared_swap.coins) == amount, ECREATED_SWAP_NOT_OURS);
            assert!(shared_swap.secret_hash == secret_hash, ECREATED_SWAP_NOT_OURS);
            assert!(shared_swap.is_fulfilled == false, ECREATED_SWAP_NOT_OURS);
            assert!(shared_swap.timelock == expiry, ECREATED_SWAP_NOT_OURS);

            // Return the shared order
            test_scenario::return_shared(shared_swap);
        };

        // Verify the order is registered in the registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry>(scenario);
            
            let order_id = create_order_id(secret_hash, initiator_address);
            assert!(orders_reg.orders.contains(order_id), ECREATED_SWAP_NOT_OURS);

            test_scenario::return_shared(orders_reg);
        };

        // Clean up
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario_val);
    }

    // Test the refund flow
    #[test]
    public fun test_refund_swap() {
        let initiator_address: address = @0xa11ce;     // Address of the initiator    
        let redeemer_address: address = @0xb0b;        // Address of the redeemer

        // The secrets
        let secret = b"ABAB";
        let secret_hash = hash::sha2_256(secret);

        let expiry: u64 = 1 * 60 * 60 * 1000;  // 1 hour in milliseconds
        let amount: u64 = 100;

        // Initializing the scenarios
        let mut scenario_val = test_scenario::begin(initiator_address);
        let scenario = &mut scenario_val;

        // Create a clock for testing
        let mut clock = clock::create_for_testing(test_scenario::ctx(scenario));

        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            create_orders_registry(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Store the initial timestamp for precise testing
        let initial_timestamp = 0;

        // Initialize the order
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Set an initial timestamp
            clock::set_for_testing(&mut clock, initial_timestamp);

            // Call initialize_Swap
            initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address,
                secret_hash,
                amount, 
                expiry,
                coins,
                &clock,
                test_scenario::ctx(scenario)
            );

            // Return the modified registry
            test_scenario::return_shared(orders_reg);
        };

        // Perform refund (advance time past expiry)
        test_scenario::next_tx(scenario, redeemer_address);
        {
            // Take the shared order
            let mut shared_swap = test_scenario::take_shared<Order<SUI>>(scenario);

            // Advance clock past the expiry time
            let refund_time = initial_timestamp + expiry + 1000;
            clock::set_for_testing(&mut clock, refund_time);

            // Verify initial state before refund
            assert!(shared_swap.is_fulfilled == false, 0);
            assert!(coin::value<SUI>(&shared_swap.coins) == amount, 0);

            // Perform refund
            refund_Swap<SUI>(&mut shared_swap, &clock, test_scenario::ctx(scenario));

            // Verify post-refund state
            assert!(shared_swap.is_fulfilled == true, 0);

            // Return the modified order
            test_scenario::return_shared(shared_swap);
        };

        // Verify refund transfer
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Check that initiator received the coins
            let refunded_coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
            assert!(coin::value(&refunded_coins) == amount, 0);

            // Return the coins
            test_scenario::return_to_sender(scenario, refunded_coins);
        };

        // Clean up
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario_val);
    }

    // Test the redeem flow
    #[test]
    public fun test_redeem_swap() {
        let initiator_address: address = @0xa11ce;     // Address of the initiator    
        let redeemer_address: address = @0xb0b;        // Address of the redeemer

        // The secrets
        let secret = b"ABAB";
        let secret_hash = hash::sha2_256(secret);

        let expiry: u64 = 1 * 60 * 60 * 1000;  // 1 hour in milliseconds
        let amount: u64 = 100;

        // Initializing the scenarios
        let mut scenario_val = test_scenario::begin(initiator_address);
        let scenario = &mut scenario_val;

        // Create a clock for testing
        let mut clock = clock::create_for_testing(test_scenario::ctx(scenario));

        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            create_orders_registry(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Store the initial timestamp for precise testing
        let initial_timestamp = 0;

        // Initialize the swap
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Set an initial timestamp
            clock::set_for_testing(&mut clock, initial_timestamp);

            // Call initialize_Swap
            initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address,
                secret_hash,
                amount, 
                expiry,
                coins,
                &clock,
                test_scenario::ctx(scenario)
            );

            // Return the modified registry
            test_scenario::return_shared(orders_reg);
        };

        // Perform redeem (advance time to just before expiry)
        test_scenario::next_tx(scenario, redeemer_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry>(scenario);

            // Take the shared swap
            let mut shared_swap = test_scenario::take_shared<Order<SUI>>(scenario);

            // Advance clock to just past the initial timestamp
            let redeem_time = initial_timestamp + expiry + 1000;
            clock::set_for_testing(&mut clock, redeem_time);

            // Verify initial state before redeem
            assert!(shared_swap.is_fulfilled == false, 0);
            assert!(coin::value<SUI>(&shared_swap.coins) == amount, 0);

            // Perform redeem
            redeem_Swap<SUI>(
                &mut shared_swap, 
                &mut orders_reg,
                secret,
                &clock, 
                test_scenario::ctx(scenario)
            );

            // Verify post-redeem state
            assert!(shared_swap.is_fulfilled == true, 0);

            // Return the modified swap and registry
            test_scenario::return_shared(shared_swap);
            test_scenario::return_shared(orders_reg);
        };

        // Verify redeem transfer
        test_scenario::next_tx(scenario, redeemer_address);
        {
            // Check that redeemer received the coins
            let redeemed_coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);
            assert!(coin::value(&redeemed_coins) == amount, 0);

            // Return the coins
            test_scenario::return_to_sender(scenario, redeemed_coins);
        };

        // Clean up
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario_val);
    }

    // // Test redeeming after order expires (it will abort)
    // #[test]
    // #[expected_failure(abort_code = ESWAP_EXPIRED)]
    // public fun test_Redeeming_after_expiry(){
    //     let initiator_address: address = @0x0;     // Address of the initiator    
    //     let redeemer_address: address = @0x1;   // Address of the redeemer

    //     // The secrets
    //     let secret = b"ABAB";
    //     let secret_hash = hash::sha2_256(secret);

    //     let expiry: u64 = 0;
    //     let amount: u64 = 100;

    //     // Initializing the scenarios
    //     let scenario_val = test_scenario::begin(initiator_address);
    //     let scenario = &mut scenario_val;

    //     let clock = clock::create_for_testing(test_scenario::ctx(scenario));

    //     let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));   // The coins we are going to give
    //     sui::transfer(coins_for_test, tx_context::initiator(test_scenario::ctx(scenario)));

    //     test_scenario::next_tx(scenario, initiator_address);

    //     let sui_Balance = test_scenario::take_from_sender<Coin<SUI>>(scenario);

    //     initialize_Swap<SUI>(
    //         redeemer_address,
    //         sui_Balance,
    //         secret_hash,
    //         amount, 
    //         expiry,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );
        
    //     test_scenario::next_tx(scenario, initiator_address);

    //     // Take the order and increment clock (for refund)
    //     // test_scenario::return_to_sender(scenario, sui_Balance);
    //     let shared_Swap = test_scenario::take_shared<Order<SUI>>(scenario);
    //     clock::increment_for_testing(&mut clock, 100);
    //     test_scenario::next_tx(scenario, initiator_address);

    //     redeem_Swap<SUI>(
    //         &mut shared_Swap,
    //         secret,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );

    //     test_scenario::return_shared(shared_Swap);
    //     test_scenario::next_tx(scenario, initiator_address);
 
    //     // boilerplate to end the test
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }

    // // Test refunding before order expires (it will abort)
    // #[test]
    // #[expected_failure(abort_code = ESWAP_NOT_EXPIRED)]
    // public fun test_Refunding_before_expiry(){
    //     let initiator_address: address = @0x0;     // Address of the initiator    
    //     let redeemer_address: address = @0x1;   // Address of the redeemer

    //     // The secrets
    //     let secret = b"ABAB";
    //     let secret_hash = hash::sha2_256(secret);

    //     let expiry: u64 = 0;
    //     let amount: u64 = 100;

    //     // Initializing the scenarios
    //     let scenario_val = test_scenario::begin(initiator_address);
    //     let scenario = &mut scenario_val;

    //     let clock = clock::create_for_testing(test_scenario::ctx(scenario));

    //     let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));   // The coins we are going to give
    //     sui::transfer(coins_for_test, tx_context::initiator(test_scenario::ctx(scenario)));

    //     test_scenario::next_tx(scenario, initiator_address);

    //     let sui_Balance = test_scenario::take_from_sender<Coin<SUI>>(scenario);

    //     initialize_Swap<SUI>(
    //         redeemer_address,
    //         sui_Balance,
    //         secret_hash,
    //         amount, 
    //         expiry,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );
        
    //     test_scenario::next_tx(scenario, initiator_address);

    //     // Take the order and increment clock (for refund)
    //     // test_scenario::return_to_sender(scenario, sui_Balance);
    //     let shared_Swap = test_scenario::take_shared<Order<SUI>>(scenario);
    //     test_scenario::next_tx(scenario, initiator_address);

    //     refund_Swap<SUI>(
    //         &mut shared_Swap,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );

    //     test_scenario::return_shared(shared_Swap);
    //     test_scenario::next_tx(scenario, initiator_address);
 
    //     // boilerplate to end the test
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }

    // // Test refunding after order has been redeemed (it will abort)
    // #[test]
    // #[expected_failure(abort_code = ESWAP_ALREADY_REDEEMED_OR_REFUNDED)]
    // public fun test_Refund_after_redeem(){
    //     let initiator_address: address = @0x0;     // Address of the initiator    
    //     let redeemer_address: address = @0x1;   // Address of the redeemer

    //     // The secrets
    //     let secret = b"ABAB";
    //     let secret_hash = hash::sha2_256(secret);

    //     let expiry: u64 = 0;
    //     let amount: u64 = 100;

    //     // Initializing the scenarios
    //     let scenario_val = test_scenario::begin(initiator_address);
    //     let scenario = &mut scenario_val;

    //     let clock = clock::create_for_testing(test_scenario::ctx(scenario));

    //     let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));   // The coins we are going to give
    //     sui::transfer(coins_for_test, tx_context::initiator(test_scenario::ctx(scenario)));


    //     test_scenario::next_tx(scenario, initiator_address);

    //     let sui_Balance = test_scenario::take_from_sender<Coin<SUI>>(scenario);

    //     initialize_Swap<SUI>(
    //         redeemer_address,
    //         sui_Balance,
    //         secret_hash,
    //         amount, 
    //         expiry,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );
        
    //     test_scenario::next_tx(scenario, initiator_address);

    //     // Take the order and increment clock (for refund)
    //     // test_scenario::return_to_sender(scenario, sui_Balance);
    //     let shared_Swap = test_scenario::take_shared<Order<SUI>>(scenario);
    //     test_scenario::next_tx(scenario, initiator_address);

    //     redeem_Swap<SUI>(
    //         &mut shared_Swap,
    //         secret,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );

    //     clock::increment_for_testing(&mut clock, 100);
    //     test_scenario::next_tx(scenario, initiator_address);

    //     refund_Swap(
    //         &mut shared_Swap,
    //         &clock,
    //         test_scenario::ctx(scenario)
    //     );

    //     test_scenario::return_shared(shared_Swap);
    //     test_scenario::next_tx(scenario, initiator_address);

    //     // boilerplate to end the test
    //     clock::destroy_for_testing(clock);
    //     test_scenario::end(scenario_val);
    // }
}