#[allow(duplicate_alias, lint(coin_field))]
module atomic_swapv1::AtomicSwap;

use 0x1::hash;
use std::vector;
use sui::address;
use sui::bcs;
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin};
use sui::dynamic_field;
use sui::event;
use sui::hash::keccak256;
use sui::hex;
use sui::object::{Self, ID, UID};
use sui::transfer;
use sui::tx_context::{Self, TxContext};
use std::string;

// ================ Error Constants ================
const EIncorrectFunds: u64 = 1;
const EOrderNotExpired: u64 = 2;
const EZeroAddressInitiator: u64 = 3;
const EZeroAddressRedeemer: u64 = 4;
const EOrderNotInitiated: u64 = 5;
const EDuplicateOrder: u64 = 7;
const EIncorrectSecret: u64 = 8;
const EInvalidTimelock: u64 = 9;
const EZeroAmount: u64 = 10;
const ESameInitiatorRedeemer: u64 = 11;
const EInvalidSecretHashLength: u64 = 13;
const EOrderFulfilled: u64 = 14;
const ESameFunderRedeemer: u64 = 15;
const ESenderNotRedeemer: u64 = 16;

// ================ Type Hash Constants ================
// keccak256() value of b"Refund(bytes32 orderId, address registry)"
const REFUND_TYPEHASH: vector<u8> =
    x"bc059cfbece4b82f519bdf7f4dea736fd886109806029923b32b99b4a698985a";

// ================ Data Structures ================
/// Represents an atomic swap order
public struct Order<phantom CoinType> has key, store {
    id: UID,
    is_fulfilled: bool,
    initiator: address,
    redeemer: address,
    amount: u64,
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
    order_id: std::string::String,
    initiator: address,
    redeemer: address,
    timelock: u256,
    secret_hash: std::string::String,
    amount: u64,
    reg_id: ID,
    destination_data: vector<u8>
}

/// Emitted when a swap is redeemed
public struct Redeemed has copy, drop {
    order_id: vector<u8>,
    secret_hash: vector<u8>,
    secret: vector<u8>,
    reg_id: ID
}

/// Emitted when a swap is refunded
public struct Refunded has copy, drop {
    order_id: vector<u8>,
    reg_id: ID
}

public struct RegistryCreated has copy, drop {
    registry_id: ID
}

// ================ Public Functions ================
/// Creates a new registry for atomic swaps of a specific coin type
/// @param ctx The transaction context
/// @return The ID of the newly created orders registry
public fun create_orders_registry<CoinType>(ctx: &mut TxContext): ID {
    let orders_reg = OrdersRegistry<CoinType> {
        id: object::new(ctx),
    };
    let orders_reg_id = object::uid_to_inner(&orders_reg.id);
    transfer::share_object(orders_reg);
    event::emit(RegistryCreated {registry_id: orders_reg_id});
    orders_reg_id
}

/// Initiates a new atomic swap on behalf of the initiator
/// @notice The tx_sender will be the funder here. Initiator and funder can be different entities.
/// @param orders_reg The registry to store the order
/// @param initiator The address of the initiator
/// @param redeemer The address of the redeemer
/// @param secret_hash The hash of the secret
/// @param amount The amount of coins to swap
/// @param timelock The time lock period for the swap (in ms)
/// @param destination_data Swap metadata
/// @param coins The coins to be swapped
/// @param clock The clock to get the current time
/// @param ctx The transaction context
public fun initiate<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    initiator: address,
    redeemer: address,
    secret_hash: vector<u8>,
    amount: u64,
    timelock: u256,
    destination_data: vector<u8>,
    coins: Coin<CoinType>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    safe_params(redeemer, initiator, amount, timelock, secret_hash, tx_context::sender(ctx));
    assert!(coin::value<CoinType>(&coins) == amount, EIncorrectFunds);
    initiate_<CoinType>(
        orders_reg,
        initiator,
        redeemer,
        secret_hash,
        amount,
        timelock,
        destination_data,
        coins,
        clock,
        ctx,
    );
}

/// Refunds tokens to the initiator after timelock has expired
/// @notice This function checks if the order is expired and not fulfilled before processing for refund
/// @param orders_reg The registry that contains the order
/// @param order_id The ID of the order to be refunded
/// @param clock The clock to get the current time
/// @param ctx The transaction context
public fun refund<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(dynamic_field::exists_(&orders_reg.id, order_id), EOrderNotInitiated);

    let reg_id = orders_reg.id.uid_to_inner();

    let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);

    assert!(!order.is_fulfilled, EOrderFulfilled);
    assert!(
        order.initiated_at + order.timelock < clock::timestamp_ms(clock) as u256,
        EOrderNotExpired,
    );

    order.is_fulfilled = true;

    event::emit(Refunded { order_id, reg_id });

    transfer::public_transfer(
        coin::split<CoinType>(&mut order.coins, order.amount, ctx),
        order.initiator,
    );
}

/// Redeems tokens by providing the secret
/// @notice This function checks if the order is not fulfilled, then verifies the secret before processing for redemption
/// @param orders_reg The registry that contains the order
/// @param order_id The ID of the order to be redeemed
/// @param secret The secret to redeem the tokens
/// @param ctx The transaction context
public fun redeem<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    secret: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(dynamic_field::exists_(&orders_reg.id, order_id), EOrderNotInitiated);
    let registry_addr = object::uid_to_address(&orders_reg.id);

    let reg_id = orders_reg.id.uid_to_inner();

    let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);
    assert!(!order.is_fulfilled, EOrderFulfilled);


    let secret_hash = hash::sha2_256(secret);
    let calc_order_id = create_order_id(
        secret_hash,
        order.initiator,
        order.redeemer,
        order.timelock,
        order.amount,
        registry_addr
    );

    assert!(calc_order_id == order_id, EIncorrectSecret);

    order.is_fulfilled = true;

    event::emit(Redeemed {
        order_id,
        secret_hash,
        secret,
        reg_id
    });

    transfer::public_transfer(
        coin::split<CoinType>(&mut order.coins, order.amount, ctx),
        order.redeemer,
    );
}

/// Performs immediate refund back to the initiator, can only be called by the redeemer
/// @notice This function checks if the order is not fulfilled before processing the refund. Allows refund before timelock expiration.
/// @param orders_reg The registry that contains the order
/// @param order_id The ID of the order to be refunded
/// @param ctx The transaction context
public fun instant_refund<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    ctx: &mut TxContext,
) {
    assert!(dynamic_field::exists_(&orders_reg.id, order_id), EOrderNotInitiated);
    
    let reg_id = orders_reg.id.uid_to_inner();
    
    let order: &mut Order<CoinType> = dynamic_field::borrow_mut(&mut orders_reg.id, order_id);

    assert!(tx_context::sender(ctx) == order.redeemer, ESenderNotRedeemer);
    assert!(!order.is_fulfilled, EOrderFulfilled);

    order.is_fulfilled = true;

    event::emit(Refunded { order_id, reg_id });

    transfer::public_transfer(
        coin::split<CoinType>(&mut order.coins, order.amount, ctx),
        order.initiator,
    );
}

// ================ Helper Functions ================

/// Creates a digest for refund verification
/// @param order_id The ID of the order to be refunded
/// @param registry_id The ID of the orders registry
/// @return The digest for refund verification
public fun instant_refund_digest(order_id: vector<u8>, registry_id: address): vector<u8> {
    encode(REFUND_TYPEHASH, order_id, address::to_bytes(registry_id))
}

// ================ Internal Functions ================

/// Validates the parameters for initiating a swap
/// @dev making sure that the secret hash is the same length as a SHA256 hash
/// @param redeemer The address of the redeemer
/// @param initiator The address of the initiator
/// @param amount The amount of coins to swap
/// @param timelock The time lock period for the swap (in ms)
fun safe_params(
    redeemer: address,
    initiator: address,
    amount: u64,
    timelock: u256,
    secret_hash: vector<u8>,
    funder: address
) {
    assert!(
        initiator != address::from_bytes(x"0000000000000000000000000000000000000000000000000000000000000000"),
        EZeroAddressInitiator,
    );
    assert!(
        redeemer != address::from_bytes(x"0000000000000000000000000000000000000000000000000000000000000000"),
        EZeroAddressRedeemer,
    );
    assert!(initiator != redeemer, ESameInitiatorRedeemer);
    assert!(funder != redeemer, ESameFunderRedeemer);
    assert!(amount != 0, EZeroAmount);
    //timelock > 0ms and <= 7 days
    assert!(timelock > 0 && timelock < 604800001, EInvalidTimelock);
    assert!(vector::length(&secret_hash) == 32, EInvalidSecretHashLength);
}

/// Creates a unique order ID based on secret hash and initiator address
/// @param secret_hash The hash of the secret
/// @param initiator The address of the initiator
/// @param redeemer The address of the redeemer
/// @param timelock The time lock period for the swap (in ms)
/// @param amount The amount to be locked for the swap
/// @param reg_id The registry ID the order will be created in.
/// @return The unique order ID
fun create_order_id(
    secret_hash: vector<u8>,
    initiator: address,
    redeemer: address,
    timelock: u256,
    amount: u64,
    reg_id: address
): vector<u8> {
    // @note sui_chain_id needs to be changed for testnet
    // sui_chain_id (testnet) = x"0000000000000000000000000000000000000000000000000000000000000001"
    let sui_chain_id = x"0000000000000000000000000000000000000000000000000000000000000000";
    let timelock_bytes = bcs::to_bytes(&timelock);
    let amount = bcs::to_bytes(&amount);
    let mut data = vector::empty<u8>();
    vector::append(&mut data, sui_chain_id);
    vector::append(&mut data, secret_hash);
    vector::append(&mut data, address::to_bytes(initiator));
    vector::append(&mut data, address::to_bytes(redeemer));
    vector::append(&mut data, timelock_bytes);
    vector::append(&mut data, amount);
    vector::append(&mut data, address::to_bytes(reg_id));
    hash::sha2_256(data)
}

/// Internal function to encode type hash with data
/// @param typehash The type hash to be encoded
/// @param order_id The ID of the order
/// @param registry_id The ID of the orders registry
/// @return The encoded data
fun encode(typehash: vector<u8>, order_id: vector<u8>, registry_id: vector<u8>): vector<u8> {
    let mut data = vector::empty<u8>();
    vector::append(&mut data, typehash);
    vector::append(&mut data, order_id);
    vector::append(&mut data, registry_id);
    keccak256(&data)
}

/// Internal function to initiate a swap
/// @notice params are passed from initiate or initiate_on_behalf
fun initiate_<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    initiator: address,
    redeemer: address,
    secret_hash: vector<u8>,
    amount: u64,
    timelock: u256,
    destination_data: vector<u8>,
    coins: Coin<CoinType>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let reg_id = object::uid_to_address(&orders_reg.id);
    let order_id = create_order_id(secret_hash, initiator, redeemer, timelock, amount, reg_id);

    assert!(!dynamic_field::exists_(&orders_reg.id, order_id), EDuplicateOrder);

    let order = Order {
        id: object::new(ctx),
        is_fulfilled: false,
        initiator,
        redeemer,
        amount,
        initiated_at: clock::timestamp_ms(clock) as u256,
        coins,
        timelock,
    };

    dynamic_field::add(&mut orders_reg.id, order_id, order);

    event::emit(Initiated {
        order_id: string::utf8(hex::encode(order_id)),
        initiator,
        redeemer,
        timelock,
        secret_hash: string::utf8(hex::encode(secret_hash)),
        amount,
        reg_id: orders_reg.id.uid_to_inner(),
        destination_data,
    });
}

// // ================================================= Test Only Getters =====================================

#[test_only]
public fun get_order<CoinType>(
    orders_reg: &OrdersRegistry<CoinType>,
    order_id: vector<u8>,
): &Order<CoinType> {
    dynamic_field::borrow(&orders_reg.id, order_id)
}
#[test_only]
public fun generate_order_id<ID: key>(
    secret_hash: vector<u8>,
    initiator: address,
    redeemer: address,
    timelock: u256,
    amount: u64,
    registry: &ID
): vector<u8> {
    let id = object::id_address(registry);
    let order_id = create_order_id(secret_hash, initiator, redeemer, timelock, amount, id);
    order_id
}
#[test_only]
public fun get_refund_typehash(): vector<u8> {
    REFUND_TYPEHASH
}
#[test_only]
public fun get_order_reg_id<CoinType>(orders_reg: &OrdersRegistry<CoinType>): &UID {
    &orders_reg.id
}
