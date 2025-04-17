module atomic_swapv1::AtomicSwap {

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

    // ================ Error Constants ================
    const EINSUFFICIENT_BALANCE: u64 = 1;
    const EORDER_EXPIRED: u64 = 2;
    const EORDER_NOT_EXPIRED: u64 = 3;
    const ESECRET_MISMATCH: u64 = 4;
    const ECREATED_SWAP_NOT_OURS: u64 = 5;
    const EORDER_FULFILLED: u64 = 6;
    const EORDER_NOT_INITIATED: u64 = 7;
    const ENOT_EMPTY: u64 = 8;
    const EINVALID_SIGNATURE: u64 = 9;
    const EDUPLICATE_ORDER: u64 = 10;
    const EINCORRECT_SECRET: u64 = 11;
    const EZERO_ADDRESS_REDEEMER: u64 = 12;
    const EZERO_TIMELOCK: u64 = 13;
    const EZERO_AMOUNT: u64 = 14;
    const ESAME_INITIATOR_REDEEMER: u64 = 15;
    const EZERO_ADDRESS_INITIATOR: u64 = 16;
    
    // ================ Type Hash Constants ================
    const REFUND_TYPEHASH: vector<u8> = b"Refund(bytes32 orderId)";
    const INITIATE_TYPEHASH: vector<u8> = b"Initiate(address redeemer,uint256 timelock,uint256 amount,bytes32 secretHash)";

    // ================ Data Structures ================
    /// Represents an atomic swap order
    public struct Order<phantom CoinType> has key, store {
        id: UID,
        is_fulfilled: bool,
        initiator: address,
        redeemer_pubk: vector<u8>,
        amount: u64,
        initiated_at: u64,
        coins: Coin<CoinType>,
        timelock: u64,
    }

    /// Central registry to store all active orders
    public struct OrdersRegistry<phantom CoinType> has key, store {
        id: UID,
        orders: ObjectTable<vector<u8>, Order<CoinType>>
    }

    // ================ Event Structs ================
    /// Emitted when a new swap is initiated
    public struct Initiated has copy, drop {
        order_id: vector<u8>,
        initiator: address,
        redeemer: address,
    }

    /// Emitted when a swap is refunded
    public struct Refunded has copy, drop {
        order_id: vector<u8>
    }

    /// Emitted when a swap is redeemed
    public struct Redeemed has copy, drop {
        order_id: vector<u8>,
        secret_hash: vector<u8>,
        secret: vector<u8>
    }

    // ================ Public Functions ================
    /// Creates a new registry for atomic swaps of a specific coin type
    public fun create_orders_registry<CoinType>(ctx: &mut TxContext): ID {
        let orders_reg = OrdersRegistry<CoinType> {
            id: object::new(ctx),
            orders: object_table::new(ctx)
        };
        let orders_reg_id = object::uid_to_inner(&orders_reg.id);
        transfer::share_object(orders_reg);
        orders_reg_id
    }

    /// Initiates a new atomic swap
    public fun initialize_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        redeemer_pubk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let redeemer = gen_addr(redeemer_pubk);
        assert!(redeemer != @0x0, EZERO_ADDRESS_REDEEMER);
        assert!(tx_context::sender(ctx) != redeemer, ESAME_INITIATOR_REDEEMER);
        assert!(amount != 0, EZERO_AMOUNT);
        assert!(timelock != 0, EZERO_TIMELOCK);
        initiate_<CoinType>(orders_reg, tx_context::sender(ctx), redeemer, redeemer_pubk, secret_hash, amount, timelock, coins, clock, ctx);
    }

    /// Initiates a swap with a signature from the initiator
    public fun initiate_with_sig<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        initiator_pubk: vector<u8>,
        redeemer_pubk: vector<u8>,
        signature: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        let initiator = gen_addr(initiator_pubk);
        let redeemer = gen_addr(redeemer_pubk);
        assert!(redeemer != @0x0, EZERO_ADDRESS_REDEEMER);
        assert!(initiator != @0x0, EZERO_ADDRESS_INITIATOR);
        assert!(initiator != redeemer, ESAME_INITIATOR_REDEEMER);
        assert!(amount != 0, EZERO_AMOUNT);
        assert!(timelock != 0, EZERO_TIMELOCK);
        let init_digest = initiate_digest(redeemer, timelock, amount, secret_hash);
        // std::debug::print(&init_digest);
        let verify = ed25519::ed25519_verify(&signature, &initiator_pubk, &init_digest);
        assert!(verify == true, EINVALID_SIGNATURE);
        initiate_<CoinType>(orders_reg, initiator, redeemer, redeemer_pubk, secret_hash, amount, timelock, coins, clock, ctx);
    }

    /// Refunds tokens to the initiator after timelock has expired
    public fun refund_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Validate order exists
        assert!(object_table::contains(&orders_reg.orders, order_id), EORDER_NOT_INITIATED);
        
        // Get order
        let order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        
        // Validate order can be refunded
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        assert!(
            clock::timestamp_ms(clock) >= order.initiated_at + order.timelock, 
            EORDER_NOT_EXPIRED
        );
        
        // Mark as fulfilled
        order.is_fulfilled = true;
        
        // Transfer coins back to initiator
        let initiator = order.initiator;
        let amount = order.amount;
        
        // Emit event
        event::emit(Refunded { order_id });
        
        // Transfer coins back to initiator
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, amount, ctx), 
            initiator
        );
    }

    /// Redeems tokens by providing the secret
    public fun redeem_Swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        secret: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Validate order exists
        assert!(object_table::contains(&orders_reg.orders, order_id), EORDER_NOT_INITIATED);
        
        // Get order
        let order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        
        // Validate order can be redeemed
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        
        // Verify secret matches
        let secret_hash = hash::sha2_256(secret);
        let calc_order_id = create_order_id(secret_hash, order.initiator);
        let redeemer = gen_addr(order.redeemer_pubk);
        assert!(calc_order_id == order_id, ESECRET_MISMATCH);
        
        // Mark as fulfilled
        order.is_fulfilled = true;
        
        // Emit event
        event::emit(Redeemed {
            order_id,
            secret_hash,
            secret
        });
        
        // Transfer coins to redeemer
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, order.amount, ctx), 
            redeemer
        );
    }

    /// Permits immediate refund if signed by the redeemer
    public fun instant_refund<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>, 
        order_id: vector<u8>, 
        signature: vector<u8>, 
        clock: &Clock, 
        ctx: &mut TxContext
    ) {
        // Validate order exists
        assert!(object_table::contains(&orders_reg.orders, order_id), EORDER_NOT_INITIATED);
        
        // Get order
        let order = object_table::borrow_mut(&mut orders_reg.orders, order_id);
        
        // Validate order is not fulfilled
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        
        // Verify signature
        let refund_digest = instant_refund_digest(order_id);
        let verified = ed25519::ed25519_verify(&signature, &order.redeemer_pubk, &refund_digest);
        assert!(verified, EINVALID_SIGNATURE);
        
        // Mark as fulfilled
        order.is_fulfilled = true;
        
        // Emit event
        event::emit(Refunded { order_id });
        
        // Transfer coins back to initiator
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, order.amount, ctx), 
            order.initiator
        );
    }

    // ================ Helper Functions ================

    /// Creates a digest for refund verification
    public fun instant_refund_digest(order_id: vector<u8>): vector<u8> {
        encode(REFUND_TYPEHASH, order_id)
    }

    /// Creates a digest for initiate verification
    public fun initiate_digest(redeemer: address, timelock: u64, amount: u64, secret_hash: vector<u8>): vector<u8> {
        let mut data = vector::empty<u8>();
        let amt_str = bcs::to_bytes(&amount);
        let tl_str = bcs::to_bytes(&timelock);
        
        vector::append(&mut data, INITIATE_TYPEHASH);
        vector::append(&mut data, address::to_bytes(redeemer));
        vector::append(&mut data, tl_str);
        vector::append(&mut data, amt_str);
        vector::append(&mut data, secret_hash);
        
        keccak256(&data)
    }

    // ================ Internal Functions ================
    /// Creates a unique order ID based on secret hash and initiator address
    fun create_order_id(secret_hash: vector<u8>, initiator: address): vector<u8> {
        let sui_chain_id = x"0000000000000000000000000000000000000000000000000000000000000000";
        
        // Prepare data for hashing
        let mut data = vector::empty<u8>();
        vector::append(&mut data, secret_hash);
        vector::append(&mut data, address::to_bytes(initiator));
        vector::append(&mut data, sui_chain_id);
        
        // Hash the data
        hash::sha2_256(data)
    }

    /// Internal function to encode type hash with data
    fun encode(typehash: vector<u8>, order_id: vector<u8>): vector<u8> {
        let mut data = vector::empty<u8>();
        vector::append(&mut data, typehash);
        vector::append(&mut data, order_id);
        keccak256(&data)
    }

    /// Internal function to generate address from a public key
    fun gen_addr(pubk: vector<u8>): address {
        // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
        let flag: u8 = 0;
        let mut preimage = vector::empty<u8>();
        vector::push_back(&mut preimage, flag);
        vector::append(&mut preimage, pubk);
        let add = blake2b256(&preimage);
        let address = address::from_bytes(add);
        address
    }

    /// Internal function to initialize a swap
    fun initiate_<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        initiator: address,
        redeemer: address,
        redeemer_pubk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u64, 
        timelock: u64,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Create order ID
        let order_id = create_order_id(secret_hash, initiator);
        
        // Check for duplication
        assert!(!object_table::contains(&orders_reg.orders, order_id), EDUPLICATE_ORDER);
        
        // Validate coins
        assert!(coin::value<CoinType>(&coins) >= amount, EINSUFFICIENT_BALANCE);
        
        // Create order
        let order = Order {
            id: object::new(ctx),
            initiator,
            is_fulfilled: false,
            redeemer_pubk,
            amount,
            initiated_at: clock::timestamp_ms(clock),
            coins,
            timelock
        };
        
        // Add to registry
        object_table::add(&mut orders_reg.orders, order_id, order);
        
        // Emit event
        event::emit(Initiated {
            order_id,
            initiator,
            redeemer
        });
        
    }
    
    // // ================================================= Test Only Getters =====================================

    #[test_only]
    public fun get_order<CoinType>(orders_reg: &OrdersRegistry<CoinType>, order_id : vector<u8>) : &Order<CoinType>{
        object_table::borrow(&orders_reg.orders, order_id)
    }
    // #[test_only]
    // public fun get_table<CoinType>(orders_reg: &OrdersRegistry<CoinType>): ObjectTable<vector<u8>, Order<CoinType>>{
    //     orders_reg.orders
    // }
    #[test_only]
    public fun generate_order_id(secret_hash: vector<u8>, initiator: address): vector<u8> {
        create_order_id(secret_hash, initiator)
    }
    #[test_only]
    public fun get_initiate_typehash(): vector<u8> {
        INITIATE_TYPEHASH
    } 
    #[test_only]
    public fun get_refund_typehash(): vector<u8> {
        REFUND_TYPEHASH
    }
}
