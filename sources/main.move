module atomic_swapv1::AtomicSwap {

    use sui::sui::{Self, SUI};                      // Sui tokens
    use sui::coin::{Self, Coin};                    // the coins
    use sui::clock::{Self, Clock};                  // To access time
    use sui::transfer;                              // To make the object publicly accessible
    use sui::event;                                 // To emit events
    use sui::table::{Self, Table};
    use sui::hash::{keccak256, blake2b256};
    use 0x1::hash;                                  // To hash the secret, for the case of redeeming
    use sui::address;
    use sui::ecdsa_k1;
    use sui::ed25519;
    use sui::object_table::{Self, ObjectTable};
    use sui::bcs;
    // Error codes, self-explanatory
    const ENOT_ENOUGH_BALANCE: u64 = 1;
    const ESWAP_EXPIRED: u64 = 2;
    const ESWAP_NOT_EXPIRED: u64 = 3;
    const ESECRET_MISMATCH: u64 = 4;
    const ECREATED_SWAP_NOT_OURS: u64 = 5;
    const ESWAP_ALREADY_REDEEMED_OR_REFUNDED: u64 = 6;
    const EORDER_NOT_FOUND: u64 = 7;
    const ENOT_EMPTY:u64 = 8;

    const REFUND_TYPEHASH: vector<u8> = b"Refund(bytes32 orderId)";
    const INITIATE_TYPEHASH: vector<u8> = b"Initiate(address redeemer,uint256 timelock,uint256 amount,bytes32 secretHash)";

    // The Order struct
    public struct Order<phantom CoinType> has key, store {
        id: UID,
        is_fulfilled: bool,
        initiator: address,
        redeemer: address,
        redeemer_pk: vector<u8>,
        amount: u64,
        initiated_at: u64,
        coins: Coin<CoinType>,
        timelock: u64,
        secret_hash: vector<u8>
    }

    public struct OrdersRegistry<phantom CoinType> has key, store {
        id: UID,
        orders: ObjectTable<vector<u8>, Order<CoinType>>
    }

    // public struct AdminCap has key { id: UID }

    // --------------------------------------- Event Structs ---------------------------------------

    // Struct for the initialized Event
    public struct Initiated has copy, drop {
        order_id: vector<u8>,
        initiator: address,
        redeemer: address,
    }

    // Struct for the refund Event
    public struct Refunded has copy, drop {
        order_id: vector<u8>,
        initiator: address,
        redeemer: address,
    }

    // Struct for the redeem Event
    public struct Redeemed has copy, drop {
            order_id: vector<u8>,
            initiator: address,
            redeemer: address,
            secret: vector<u8>
    }

    fun init(ctx: &mut TxContext) {
        // transfer::transfer(
        //     AdminCap { id: object::new(ctx) },
        //     ctx.sender()
        // );
    }

    public fun create_orders_registry<CoinType>(ctx: &mut TxContext): ID{
        let orders_reg = OrdersRegistry<CoinType> {
            id: object::new(ctx),
            orders: object_table::new(ctx)
        };
        let orders_reg_id = object::uid_to_inner(&orders_reg.id);
        transfer::share_object(orders_reg);
        orders_reg_id
    }

    public fun create_order_id(secret_hash: vector<u8>, initiator: address): vector<u8> {
        let sui_chain_id = x"0000000000000000000000000000000000000000000000000000000000000000";
        // Convert the address to a vector<u8> manually
        let mut address_bytes = vector::empty<u8>();
        let address_vec: vector<u8> = address::to_bytes(initiator); 
        vector::append(&mut address_bytes, address_vec);
        // vector::append
        // Concatenate the secret_hash and address_bytes
        let mut data = vector::empty<u8>();
        vector::append(&mut data, secret_hash);
        vector::append(&mut data, address_bytes);
        // Concatenate SUI mainnet id
        vector::append(&mut data, sui_chain_id);
        // Compute the SHA256 hash of the concatenated data
        let hash_result: vector<u8> = hash::sha2_256(data);
        hash_result
    }
    // Creates a order object and makes it a shared_object
    public fun initialize_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        redeemer: address,
        redeemer_pk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ): vector<u8> {
        // Check that value of coins exceeds amount in order
        assert!(coin::value<CoinType>(&coins) >= amount, ENOT_ENOUGH_BALANCE);

        let id = object::new(ctx);
        let object_id = object::uid_to_inner(&id);
        let order_id = create_order_id(secret_hash, ctx.sender());

        // Check if the order_id already exists
        // assert!(!table::contains(&orders_reg.orders, order_id), EDUPLICATE_ORDER);

        // Emit event
        event::emit(Initiated {
            order_id: order_id,
            initiator: tx_context::sender(ctx),
            redeemer: redeemer
        });
        // get the required amount out of the users balance
        let order = Order {
            id: id,
            initiator: tx_context::sender(ctx),                                 // The address of the initiator 
            is_fulfilled: false,                                                // Create a new ID for the object
            redeemer: redeemer,                                                 // The address of the redeemer
            redeemer_pk: redeemer_pk,
            amount: amount,                                                     // The amount being locked for swap
            secret_hash: secret_hash,                                           // The hashed secret
            initiated_at: clock::timestamp_ms(clock),                           // The amount to be transferred
            coins,                                                              // The coins where value(coins) == amount
            timelock                                                            // THe expiry, being (timelock) hours away from initialization time
        };
        
        ////////////////
        // let obj_id = order.borrow_uid();
        ////////////////

        orders_reg.orders.add(order_id, order);
        // Share the object so anyone can access nad mutate it
        // transfer::share_object<Order<CoinType>>(order);
        order_id
    }

    public fun initiate_digest(redeemer: address, timelock: u64, amount: u64, secret_hash: vector<u8>): vector<u8>{
        let mut data = vector::empty<u8>();
        let amt = amount.to_string().into_bytes();
        let tl = timelock.to_string().into_bytes();
        vector::append(&mut data, INITIATE_TYPEHASH);
        vector::append(&mut data, redeemer.to_bytes());
        vector::append(&mut data, tl);
        vector::append(&mut data, amt);
        vector::append(&mut data, secret_hash);
        // Compute the keccak256 of the concatenated data
        let hash_result: vector<u8> = keccak256(&data);
        hash_result
    }

    public fun initiate_with_sig<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        initiator: address,
        initiator_pubk: vector<u8>,
        redeemer: address,
        redeemer_pubk: vector<u8>,
        signature: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ): vector<u8> {
        // Check that value of coins exceeds amount in order
        assert!(coin::value<CoinType>(&coins) >= amount, ENOT_ENOUGH_BALANCE);
        let init_digest = initiate_digest(redeemer, timelock, amount, secret_hash);
        let verify = ed25519::ed25519_verify(&signature, &initiator_pubk, &init_digest);
        assert!(verify == true, 0);
        
        let id = object::new(ctx);
        let object_id = object::uid_to_inner(&id);
        let order_id = create_order_id(secret_hash, initiator);
        // Check if the order_id already exists
        // assert!(!table::contains(&orders_reg.orders, order_id), EDUPLICATE_ORDER);

        // Emit event
        event::emit(Initiated {
            order_id: order_id,
            initiator: initiator,
            redeemer: redeemer
        });
        // get the required amount out of the users balance
        let order = Order {
            id: id,
            initiator: initiator,                                 // The address of the initiator 
            is_fulfilled: false,                                                // Create a new ID for the object
            redeemer: redeemer,                                                 // The address of the redeemer
            redeemer_pk: redeemer_pubk,
            amount: amount,                                                     // The amount being locked for swap
            secret_hash: secret_hash,                                           // The hashed secret
            initiated_at: clock::timestamp_ms(clock),                           // The amount to be transferred
            coins,                                                              // The coins where value(coins) == amount
            timelock                                                            // THe expiry, being (timelock) hours away from initialization time
        };
        
        ////////////////
        // let obj_id = order.borrow_uid();
        ////////////////

        orders_reg.orders.add(order_id, order);
        // Share the object so anyone can access nad mutate it
        // transfer::share_object<Order<CoinType>>(order);
        order_id
    }

    // Refunds the coins and destroys Order object
    public fun refund_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        let mut order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        // Makes sure that order has expired
        assert!(clock::timestamp_ms(clock) >= order.initiated_at + order.timelock, ESWAP_NOT_EXPIRED);
        assert!(order.is_fulfilled == false, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);
        // If coins are 0, then order has been used
        assert!(coin::value<CoinType>(&order.coins) > 0, ESWAP_ALREADY_REDEEMED_OR_REFUNDED);
        // Unpack the Order object, only need initiator, coins and id (it cant be dropped) so the rest are all _ 
        let amount = order.amount;
        let initiator = order.initiator;
        order.is_fulfilled = true;

        // Emit event
        event::emit(Refunded {
            order_id: order_id,
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
    public fun redeem_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        secret: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        assert!(object_table::contains(&orders_reg.orders, order_id), EORDER_NOT_FOUND);
        let mut order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        // Makes sure that order has not expired
        assert!(clock::timestamp_ms(clock) < order.timelock + order.initiated_at, ESWAP_EXPIRED);
        // Ensure that the secret sent, after hashing, is same as the hashed_secret we have stored
        let secret_hash = hash::sha2_256(secret);
        assert!(order.secret_hash == secret_hash, ESECRET_MISMATCH);
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

        order.is_fulfilled = true;
        
        // Emit event
        event::emit(Redeemed {
            order_id: order_id,
            initiator: order.initiator,
            redeemer: order.redeemer,
            secret: secret
        });
    }

    public fun instant_refund<CoinType>(orders_reg: &mut OrdersRegistry<CoinType>, order_id: vector<u8>, signature: vector<u8>, clock: &Clock, ctx: &mut TxContext){
        assert!(object_table::contains(&orders_reg.orders, order_id), EORDER_NOT_FOUND);
        let mut order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        let refund_digest = instant_refund_digest(order_id);
        let verify = ed25519::ed25519_verify(&signature, &order.redeemer_pk, &refund_digest);
        assert!(verify == true, 0);
        assert!(order.is_fulfilled == false, 0);
        
        order.is_fulfilled = true;

        // Emit event
        event::emit(Refunded {
            order_id: order_id,
            initiator: order.initiator,
            redeemer: order.redeemer
        });

        // Transfer the coins to the initiator
        transfer::public_transfer(
            coin::split<CoinType>(
                &mut order.coins,
                order.amount,
                ctx
            ), 
            order.initiator
        );
    }

    public fun instant_refund_digest(order_id: vector<u8>) : vector<u8> {
        // let bytes: vector<u8> = keccak256(&REFUND_TYPEHASH);
        encode(REFUND_TYPEHASH, order_id)
    }
    public fun encode(typehash: vector<u8>, order_id: vector<u8>) : vector<u8> {
        // Concatenate the typehash and order_id
        let mut data = vector::empty<u8>();
        vector::append(&mut data, typehash);
        vector::append(&mut data, order_id);

        // Compute the SHA256 hash of the concatenated data
        let hash_result: vector<u8> = keccak256(&data);
        hash_result
    }
    
    
    // // ================================================= Tests ================================================= 

    #[test_only]
    use sui::test_scenario;
    use bridge::crypto;

    #[test]
    public fun test_create_orders_registry() {
        let pub_address: address = @0xb0b;
        let mut scenario_val = test_scenario::begin(pub_address);
        let scenario = &mut scenario_val;
        let mut reg_add: ID;
        test_scenario::next_tx(scenario, pub_address);
        {
            reg_add = create_orders_registry<SUI>(test_scenario::ctx(scenario));
        };

        // Next transaction to verify the registry
        test_scenario::next_tx(scenario, pub_address);
        {
            let registry = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let OrdersRegistry{id, orders} = &registry;
            assert!(object_table::is_empty(orders), 0);
            assert!(object::uid_to_inner(id) == reg_add, 0);
            test_scenario::return_shared(registry);
        };

        test_scenario::end(scenario_val);
    }

    // Test just the initialization part of it
    #[test]
    public fun test_initialize_swap() {
        let initiator_address: address = @0xa11ce;     // Address of the initiator    
        let redeemer_address: address = @0xb0b;        // Address of the redeemer
        let false_redeemer_pk: vector<u8> = x"00";
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
        let mut reg_add: ID;
        
        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            reg_add = create_orders_registry<SUI>(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Initialize the order
        let mut order_id: vector<u8>;
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Call initialize_Swap
            order_id = initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address, false_redeemer_pk,
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

        // Verify the order in the registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Check that the order exists in the registry
            assert!(object_table::contains(&orders_reg.orders, order_id), ECREATED_SWAP_NOT_OURS);
            
            // Borrow the order to verify its fields
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            // Assertions
            assert!(order.initiator == initiator_address, ECREATED_SWAP_NOT_OURS);
            assert!(order.redeemer == redeemer_address, ECREATED_SWAP_NOT_OURS);
            assert!(coin::value(&order.coins) == amount, ECREATED_SWAP_NOT_OURS);
            assert!(order.secret_hash == secret_hash, ECREATED_SWAP_NOT_OURS);
            assert!(order.is_fulfilled == false, ECREATED_SWAP_NOT_OURS);
            assert!(order.timelock == expiry, ECREATED_SWAP_NOT_OURS);

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
            create_orders_registry<SUI>(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Store the initial timestamp for precise testing
        let initial_timestamp = 0;
        let false_redeemer_pk: vector<u8> = x"00";
        // Initialize the order
        let mut order_id: vector<u8>;
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Set an initial timestamp
            clock::set_for_testing(&mut clock, initial_timestamp);

            // Call initialize_Swap
            order_id = initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address, false_redeemer_pk,
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

        // Verify order state before refund
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            assert!(order.is_fulfilled == false, 0);
            assert!(coin::value(&order.coins) == amount, 0);
            
            test_scenario::return_shared(orders_reg);
        };

        // Perform refund (advance time past expiry)
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);

            // Advance clock past the expiry time
            let refund_time = initial_timestamp + expiry + 1000;
            clock::set_for_testing(&mut clock, refund_time);

            // Perform refund
            refund_Swap<SUI>(
                &mut orders_reg,
                order_id,
                &clock,
                test_scenario::ctx(scenario)
            );

            // Return the modified registry
            test_scenario::return_shared(orders_reg);
        };

        // Verify post-refund state
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            // Verify the order is marked as fulfilled
            assert!(order.is_fulfilled == true, 0);
            
            test_scenario::return_shared(orders_reg);
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
        let false_redeemer_pk: vector<u8> = x"00";
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
        // Store the initial timestamp for precise testing
        let initial_timestamp = 0;
        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            create_orders_registry<SUI>(test_scenario::ctx(scenario));
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
        let mut order_id: vector<u8>;
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Set an initial timestamp
            clock::set_for_testing(&mut clock, initial_timestamp);

            // Call initialize_Swap
            order_id = initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address, false_redeemer_pk,
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

        // Verify order state before redeem
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            assert!(order.is_fulfilled == false, 0);
            assert!(coin::value(&order.coins) == amount, 0);
            
            test_scenario::return_shared(orders_reg);
        };

        // Perform redeem
        test_scenario::next_tx(scenario, redeemer_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);

            
            // Advance clock to just past the initial timestamp
            let redeem_time = initial_timestamp + expiry - 1;
            clock::set_for_testing(&mut clock, redeem_time);

            // Perform redeem
            redeem_Swap<SUI>(
                &mut orders_reg,
                order_id,
                secret,
                &clock,
                test_scenario::ctx(scenario)
            );

            // Return the modified registry
            test_scenario::return_shared(orders_reg);
        };

        // Verify post-redeem state
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            // Verify the order is marked as fulfilled
            assert!(order.is_fulfilled == true, 0);
            
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

    // Test the instant refund flow
    #[test]
    public fun test_instant_refund() {
        let initiator_address: address = @0xa11ce;   
        // Create a test keypair for the redeemer (using fastcrypto cli)
        let redeemer_sk: vector<u8> = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
        let redeemer_pk: vector<u8> = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
        let flag: u8 = 0; // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
        let mut preimage: vector<u8> = vector::empty<u8>();
        vector::push_back(&mut preimage, flag);
        vector::append(&mut preimage, redeemer_pk);
        let redeemer_add = blake2b256(&preimage);
        let redeemer_address = address::from_bytes(redeemer_add);
        std::debug::print(&redeemer_address);
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
            create_orders_registry<SUI>(test_scenario::ctx(scenario));
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
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            // Set an initial timestamp
            clock::set_for_testing(&mut clock, initial_timestamp);

            // Call initialize_Swap with our derived redeemer address
            initialize_Swap<SUI>(
                &mut orders_reg, 
                redeemer_address, redeemer_pk,
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
        
        let mut order_id = create_order_id(secret_hash, initiator_address);
        let refund_digest = instant_refund_digest(order_id);

        //we calulate the digest and sign it off-chain (fastcrypto-cli used here)
        std::debug::print(&refund_digest); //0x1556fee926652c2be9251a8f235c142ec336ad66a89a27d39f5877f884fc9ac7
        let signature = x"efc727690a97bb47058e36156646f0129977697607b7d8bc605bcd3e516d14280b841cfea6a5ee72863604de5602c8e1ad75c4fb7efb2e7d2e2b5f7658b46e0e";
        
        // Verify order state before refund
        test_scenario::next_tx(scenario, initiator_address);
        {
            let orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            assert!(order.is_fulfilled == false, 0);
            assert!(coin::value<SUI>(&order.coins) == amount, 0);
            
            test_scenario::return_shared(orders_reg);
        };

        // Perform instant refund
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);

            // Perform instant refund with our signature
            instant_refund<SUI>(
                &mut orders_reg, 
                order_id, 
                signature, 
                &clock, 
                test_scenario::ctx(scenario)
            );
            let order = object_table::borrow(&orders_reg.orders, order_id);
            // Verify post-refund state
            assert!(order.is_fulfilled == true, 0);

            // Return the modified objects
            test_scenario::return_shared(orders_reg);
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

    #[test]
    public fun test_init_with_sig(){
        let redeemer_address: address = @0xb0b;        // Address of the redeemer
        let redeemer_false_pk: vector<u8> = x"123456";
        let initiator_sk: vector<u8> = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
        let initiator_pk: vector<u8> = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
        let flag: u8 = 0; // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
        let mut preimage: vector<u8> = vector::empty<u8>();
        vector::push_back(&mut preimage, flag);
        vector::append(&mut preimage, initiator_pk);
        let initiator_add = blake2b256(&preimage);
        let initiator_address = address::from_bytes(initiator_add);
        std::debug::print(&initiator_address);
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
        let mut reg_add: ID;
        
        // Create orders registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            reg_add = create_orders_registry<SUI>(test_scenario::ctx(scenario));
        };

        // Mint and transfer coins
        test_scenario::next_tx(scenario, initiator_address);
        {
            let coins_for_test = coin::mint_for_testing<SUI>(amount, test_scenario::ctx(scenario));
            transfer::public_transfer(coins_for_test, initiator_address);
        };

        // Initialize the order
        let mut order_id: vector<u8>;
        let signature = x"3c671a57d6c991e06f735d29d9c24dc42b3a42064e80afec0423beea80d0597f2e1885699c1d89ce08bc5b26f4665d4fe3f4efd1de8e23fadf67970e6f9a7a00";
        test_scenario::next_tx(scenario, initiator_address);
        {
            // Take the orders registry
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Take the coins from sender
            let coins = test_scenario::take_from_sender<Coin<SUI>>(scenario);

            let digest = initiate_digest(redeemer_address, expiry, amount, secret_hash);
            std::debug::print(&digest);
            let m = b"-----yahaapedekh";
            std::debug::print(&m);
            // Call initialize_Swap
            order_id = initiate_with_sig<SUI>(
                &mut orders_reg, 
                initiator_address,
                initiator_pk,
                redeemer_address, 
                redeemer_false_pk,
                signature,
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

        // Verify the order in the registry
        test_scenario::next_tx(scenario, initiator_address);
        {
            let mut orders_reg = test_scenario::take_shared<OrdersRegistry<SUI>>(scenario);
            
            // Check that the order exists in the registry
            assert!(object_table::contains(&orders_reg.orders, order_id), ECREATED_SWAP_NOT_OURS);
            
            // Borrow the order to verify its fields
            let order = object_table::borrow(&orders_reg.orders, order_id);
            
            // Assertions
            assert!(order.initiator == initiator_address, ECREATED_SWAP_NOT_OURS);
            assert!(order.redeemer == redeemer_address, ECREATED_SWAP_NOT_OURS);
            assert!(coin::value(&order.coins) == amount, ECREATED_SWAP_NOT_OURS);
            assert!(order.secret_hash == secret_hash, ECREATED_SWAP_NOT_OURS);
            assert!(order.is_fulfilled == false, ECREATED_SWAP_NOT_OURS);
            assert!(order.timelock == expiry, ECREATED_SWAP_NOT_OURS);

            test_scenario::return_shared(orders_reg);
        };

        // Clean up
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario_val);
    }

    #[test]
    public fun test_whiteboard() {
        // let secret = b"ABABCBA";
        // let secret_hash = hash::sha2_256(secret);
        // std::debug::print(&secret_hash);
        // let add: address = @0x6327b12f0e672c857cf562e9d3ac96e488b921e9e91d5b3f5bf0e8f54707ea11;
        // let res = create_order_id(secret_hash, add);
        // std::debug::print(&res);
        
        // let pk = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";
        // let flag: u8 = 1; // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
        // let mut preimage: vector<u8> = vector::empty<u8>();
        // vector::push_back(&mut preimage, flag);
        // vector::append(&mut preimage, pk);
        // let redeemer = blake2b256(&preimage);
        // std::debug::print(&redeemer);
        // let redeemer_address = address::from_bytes(redeemer);
        // std::debug::print(&redeemer_address);

        // let msg = x"f5737cf6698a26ce7fe25cf8359daed98d76cec7de5d7c6c7fd6c4ce34b2314d";
        // let pk = x"9c8edcc5989fa5747d1454c41015192ebb96308d3b48fa98d949b49cd1b22210";
        
        let redeemer = @0x054978ec2cf9219920af04e9a756d3518c4dee3c4d4198561f6a7c8e7d84c094;
        let timelock = 3 * 60 * 1000;
        let amount = 10000;
        let secret = b"test7";
        let secret_hash = hash::sha2_256(secret);
        let digest = initiate_digest(redeemer, timelock, amount, secret_hash);
        std::debug::print(&digest);
    }
}