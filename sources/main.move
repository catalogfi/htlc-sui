#[allow(duplicate_alias, lint(coin_field))]
module atomic_swapv1::AtomicSwap {
    use sui::{
        coin::{Self, Coin},
        clock::{Self, Clock},
        transfer,
        event,
        address,
        ed25519,
        bcs,
        object::{Self, ID, UID},
        hash::{keccak256, blake2b256},
        dynamic_field::{Self},
        tx_context::{Self, TxContext}
    };
    use std::vector;
    use 0x1::hash;

    // ================ Error Constants ================
    const EINCORRECT_FUNDS: u64 = 1;
    const EORDER_NOT_EXPIRED: u64 = 2;
    const EZERO_ADDRESS_INITIATOR: u64 = 3;
    const EORDER_FULFILLED: u64 = 4;
    const EORDER_NOT_INITIATED: u64 = 5;
    const EINVALID_SIGNATURE: u64 = 6;
    const EDUPLICATE_ORDER: u64 = 7;
    const EINCORRECT_SECRET: u64 = 8;
    const EZERO_ADDRESS_REDEEMER: u64 = 9;
    const EZERO_TIMELOCK: u64 = 10;
    const EZERO_AMOUNT: u64 = 11;
    const ESAME_INITIATOR_REDEEMER: u64 = 12;
    const ESAME_FUNDER_REDEEMER: u64 = 13;
    const EINVALID_PUBKEY: u64 = 14;
    
    // ================ Type Hash Constants ================
    const REFUND_TYPEHASH: vector<u8> = b"Refund(bytes32 orderId)";

    // ================ Data Structures ================
    /// Represents an atomic swap order
    public struct Order<phantom CoinType> has key, store {
        id: UID,
        is_fulfilled: bool,
        initiator: address,
        redeemer_pubk: vector<u8>,
        amount: u256,
        initiated_at: u256,
        coins: Coin<CoinType>,
        timelock: u256,
    }

    /// Central registry to store all active orders
    public struct OrdersRegistry<phantom CoinType> has key, store {
        id: UID,
    }

    // ================ Event Structs ================
    /// Emitted when a new swap is initiated
    public struct Initiated has copy, drop {
        order_id: vector<u8>,
        secret_hash: vector<u8>,
        amount: u256
    }

    /// Emitted when a swap is redeemed
    public struct Redeemed has copy, drop {
        order_id: vector<u8>,
        secret_hash: vector<u8>,
        secret: vector<u8>
    }

    /// Emitted when a swap is refunded
    public struct Refunded has copy, drop {
        order_id: vector<u8>
    }

    // ================ Public Functions ================
    /// Creates a new registry for atomic swaps of a specific coin type
    public fun create_orders_registry<CoinType>(ctx: &mut TxContext): ID {
        let orders_reg = OrdersRegistry<CoinType> {
            id: object::new(ctx),
        };
        let orders_reg_id = object::uid_to_inner(&orders_reg.id);
        transfer::share_object(orders_reg);
        orders_reg_id
    }

    /// Initiates a new atomic swap
    public fun initiate<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        redeemer_pubk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u256, 
        timelock: u256,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let redeemer = gen_addr(redeemer_pubk);
        safe_params(redeemer, tx_context::sender(ctx), amount, timelock);
        assert!(coin::value<CoinType>(&coins) as u256 == amount, EINCORRECT_FUNDS);
        initiate_<CoinType>(orders_reg, tx_context::sender(ctx), redeemer, redeemer_pubk, secret_hash, amount, timelock, coins, clock, ctx);
    }

    public fun initiate_on_behalf<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        initiator: address,
        redeemer_pubk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u256, 
        timelock: u256,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ){
        let redeemer = gen_addr(redeemer_pubk);
        assert!(tx_context::sender(ctx) != redeemer, ESAME_FUNDER_REDEEMER);
        safe_params(redeemer, initiator, amount, timelock);
        assert!(coin::value<CoinType>(&coins) as u256 == amount, EINCORRECT_FUNDS);
        initiate_<CoinType>(orders_reg, initiator, redeemer, redeemer_pubk, secret_hash, amount, timelock, coins, clock, ctx);
    }

    /// Refunds tokens to the initiator after timelock has expired
    public fun refund_swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(dynamic_field::exists_(&orders_reg.id, order_id), EORDER_NOT_INITIATED);
        
        let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);
        
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        assert!(
            order.initiated_at + order.timelock < clock::timestamp_ms(clock) as u256, 
            EORDER_NOT_EXPIRED
        );
        
        order.is_fulfilled = true;
        
        event::emit(Refunded { order_id });
        
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, order.amount as u64, ctx), 
            order.initiator
        );
    }

    /// Redeems tokens by providing the secret
    public fun redeem_swap<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        order_id: vector<u8>,
        secret: vector<u8>,
        // clock: &Clock,
        ctx: &mut TxContext
    ) {
        assert!(dynamic_field::exists_(&orders_reg.id, order_id), EORDER_NOT_INITIATED);
        
        let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);
        
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        
        let redeemer = gen_addr(order.redeemer_pubk);
        let secret_hash = hash::sha2_256(secret);
        let calc_order_id = create_order_id(secret_hash, order.initiator, order.timelock, redeemer);

        assert!(calc_order_id == order_id, EINCORRECT_SECRET);
        
        order.is_fulfilled = true;
        
        event::emit(Redeemed {
            order_id,
            secret_hash,
            secret
        });
        
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, order.amount as u64, ctx), 
            redeemer
        );
    }

    // @audit-ok currently we only support Ed25519
    /// Permits immediate refund if signed by the redeemer
    public fun instant_refund<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>, 
        order_id: vector<u8>, 
        signature: vector<u8>, 
        // clock: &Clock, 
        ctx: &mut TxContext
    ) {
        assert!(dynamic_field::exists_(&orders_reg.id, order_id), EORDER_NOT_INITIATED);
        
        let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);
        
        assert!(!order.is_fulfilled, EORDER_FULFILLED);
        
        let refund_digest = instant_refund_digest(order_id);
        let verified = ed25519::ed25519_verify(&signature, &order.redeemer_pubk, &refund_digest);
        assert!(verified, EINVALID_SIGNATURE);
        
        order.is_fulfilled = true;
        
        event::emit(Refunded { order_id });
        
        transfer::public_transfer(
            coin::split<CoinType>(&mut order.coins, order.amount as u64, ctx), 
            order.initiator
        );
    }

    // ================ Helper Functions ================

    /// Creates a digest for refund verification
    public fun instant_refund_digest(order_id: vector<u8>): vector<u8> {
        let refund_typehash = REFUND_TYPEHASH;
        encode(keccak256(&refund_typehash), order_id)
    }

    // ================ Internal Functions ================

    fun safe_params(redeemer: address, initiator: address, amount: u256, timelock: u256){
        assert!(redeemer != @0x0, EZERO_ADDRESS_REDEEMER);
        assert!(initiator != redeemer, ESAME_INITIATOR_REDEEMER);
        assert!(amount != 0, EZERO_AMOUNT);
        assert!(timelock != 0, EZERO_TIMELOCK);
        assert!(initiator != @0x0, EZERO_ADDRESS_INITIATOR);
    }
    /// Creates a unique order ID based on secret hash and initiator address
    fun create_order_id(secret_hash: vector<u8>, initiator: address, timelock: u256, redeemer: address): vector<u8> {
        let sui_chain_id = x"0000000000000000000000000000000000000000000000000000000000000000";
        let timelock_bytes = bcs::to_bytes(&timelock);

        let mut data = vector::empty<u8>();
        vector::append(&mut data, sui_chain_id);
        vector::append(&mut data, secret_hash);
        vector::append(&mut data, address::to_bytes(initiator));
        vector::append(&mut data, timelock_bytes);
        vector::append(&mut data, address::to_bytes(redeemer));
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
        assert!(vector::length(&pubk) == 32, EINVALID_PUBKEY);
        let flag: u8 = 0;
        let mut preimage = vector::empty<u8>();
        vector::push_back(&mut preimage, flag);
        vector::append(&mut preimage, pubk);
        let addr = blake2b256(&preimage);
        address::from_bytes(addr)
    }

    /// Internal function to initiate a swap
    fun initiate_<CoinType>(
        orders_reg: &mut OrdersRegistry<CoinType>,
        initiator: address,
        redeemer: address,
        redeemer_pubk: vector<u8>,
        secret_hash: vector<u8>,
        amount: u256, 
        timelock: u256,
        coins: Coin<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let order_id = create_order_id(secret_hash, initiator, timelock, redeemer);
        
        assert!(!dynamic_field::exists_(&orders_reg.id, order_id), EDUPLICATE_ORDER);
        
        let order = Order {
            id: object::new(ctx),
            initiator,
            is_fulfilled: false,
            redeemer_pubk,
            amount,
            initiated_at: clock::timestamp_ms(clock) as u256,
            coins,
            timelock
        };
        
        dynamic_field::add(&mut orders_reg.id, order_id, order);
        
        event::emit(Initiated {
            order_id,
            secret_hash,
            amount
        });
        
    }
    
    // // ================================================= Test Only Getters =====================================

    #[test_only]
    public fun get_order<CoinType>(orders_reg: &OrdersRegistry<CoinType>, order_id : vector<u8>) : &Order<CoinType>{
        dynamic_field::borrow(&orders_reg.id, order_id)
    }
    #[test_only]
    public fun generate_order_id(secret_hash: vector<u8>, initiator: address, timelock: u256, redeemer: address): vector<u8> {
        create_order_id(secret_hash, initiator, timelock, redeemer)
    }
    #[test_only]
    public fun get_refund_typehash(): vector<u8> {
        REFUND_TYPEHASH
    }
}
