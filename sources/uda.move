module atomic_swapv1::UDA;

use atomic_swapv1::AtomicSwap;
use std::string;
use std::type_name;
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin};
use sui::event;
use sui::hex;
use sui::table::{Self, Table};
use sui::transfer::Receiving;

const EInvalidRegistry: u64 = 1;
const EDeadlineNotYetExpired: u64 = 2;
const EInvalidCoins: u64 = 3;
const EDeadlineExpired: u64 = 4;
const EZeroAmount: u64 = 5;
const EZeroTimelock: u64 = 6;
const EInvalidSecretHashLength: u64 = 7;
const EZeroDeadline: u64 = 8;
const EInvalidTimelock: u64 = 9;
const ESameInitiatorRedeemer: u64 = 10;
const EZeroAddressInitiator: u64 = 11;
const EZeroAddressRedeemer: u64 = 12;
const ESameFunderRedeemer: u64 = 13;
const EDuplicateOrder: u64 = 14;
const EInsufficientFunds: u64 = 15;

public struct UDACreated has copy, drop {
    reg_id: address,
    uda_id: address,
    initiator: address,
}

public struct UDAInitiated has copy, drop {
    uda_id: address,
    secret_hash: string::String,
}

public struct TableMapping has copy, drop {
    mapping_id: address,
}

public struct AdminCap has key, store {
    id: UID,
}

public struct InitiateObject<phantom CoinType> has key, store {
    id: UID,
    initiator: address,
    redeemer: address,
    secret_hash: vector<u8>,
    amount: u64,
    timelock: u256,
    destination_data: vector<u8>,
    reg_address: address,
    created_at: u256,
    deadline: u256,
}

public struct RegistryMapping has key, store {
    id: UID,
    table: Table<type_name::TypeName, address>,
}

fun init(ctx: &mut TxContext) {
    let admin = AdminCap {
        id: object::new(ctx),
    };
    transfer::public_transfer(admin, tx_context::sender(ctx));
    let valid_registry = RegistryMapping {
        id: object::new(ctx),
        table: table::new(ctx),
    };
    let registry_id = object::uid_to_address(&valid_registry.id);
    transfer::share_object(valid_registry);
    event::emit(TableMapping {
        mapping_id: registry_id,
    });
}

public fun add_reg_id<CoinType>(
    _: &mut AdminCap,
    obj: &mut RegistryMapping,
    mapped_addr: address,
    _ctx: &mut TxContext,
) {
    let tn = type_name::with_defining_ids<CoinType>();
    if (table::contains(&obj.table, tn)) {
        table::remove(&mut obj.table, tn);
    };
    table::add(&mut obj.table, tn, mapped_addr);
}

public fun get_reg_id<CoinType>(obj: &RegistryMapping): address {
    let tn = type_name::with_defining_ids<CoinType>();
    *table::borrow(&obj.table, tn)
}

public fun create_object<CoinType>(
    initiator: address,
    redeemer: address,
    secret_hash: vector<u8>,
    amount: u64,
    timelock: u256,
    destination_data: vector<u8>,
    valid_registry: &mut RegistryMapping,
    reg: &mut AtomicSwap::OrdersRegistry<CoinType>,
    deadline: u256,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let valid_reg_address = get_reg_id<CoinType>(valid_registry);
    let (reg_address, reg) = AtomicSwap::get_order_reg_address(reg);
    safe_params(
        initiator,
        redeemer,
        amount,
        timelock,
        secret_hash,
        deadline,
        valid_reg_address,
        reg,
        ctx,
    );
    assert!(reg_address == valid_reg_address, EInvalidRegistry);
    let obj = InitiateObject<CoinType> {
        id: object::new(ctx),
        initiator,
        redeemer,
        secret_hash,
        amount,
        timelock,
        destination_data,
        reg_address: valid_reg_address,
        created_at: clock::timestamp_ms(clock) as u256,
        deadline,
    };
    let uda_id = object::uid_to_address(&obj.id);
    let initiator = obj.initiator;
    transfer::share_object(obj);
    event::emit(UDACreated {
        reg_id: valid_reg_address,
        uda_id,
        initiator,
    });
}

public fun initialize<CoinType>(
    obj: &mut InitiateObject<CoinType>,
    sent: vector<Receiving<Coin<CoinType>>>,
    reg: &mut AtomicSwap::OrdersRegistry<CoinType>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    assert!(sent.length() > 0, EInvalidCoins);
    // assert!(clock::timestamp_ms(clock) as u256 < obj.created_at + obj.deadline, EDeadlineExpired);
    let (reg_address, reg) = AtomicSwap::get_order_reg_address(reg);
    assert!(reg_address == obj.reg_address, EInvalidRegistry);
    let mut coin = merge_coins(obj, sent, ctx);
    assert!(coin::value(&coin) == obj.amount, EInsufficientFunds);
    let split_coin = coin::split<CoinType>(&mut coin, obj.amount, ctx);
    AtomicSwap::initiate<CoinType>(
        reg,
        obj.initiator,
        obj.redeemer,
        obj.secret_hash,
        obj.amount,
        obj.timelock,
        obj.destination_data,
        split_coin,
        clock,
        ctx,
    );
    transfer::public_transfer(coin, obj.initiator);
    event::emit(UDAInitiated {
        uda_id: object::uid_to_address(&obj.id),
        secret_hash: string::utf8(hex::encode(obj.secret_hash)),
    });
}

fun merge_coins<CoinType>(
    obj: &mut InitiateObject<CoinType>,
    mut sent: vector<Receiving<Coin<CoinType>>>,
    _ctx: &mut TxContext,
): Coin<CoinType> {
    let mut coins = vector::empty<Coin<CoinType>>();
    let len = vector::length(&sent);
    let mut i = 0;
    while (i < len) {
        let coin = transfer::public_receive(&mut obj.id, vector::pop_back(&mut sent));
        vector::push_back(&mut coins, coin);
        i = i + 1;
    };
    let mut main_coin = vector::pop_back(&mut coins);
    sui::pay::join_vec(&mut main_coin, coins);
    main_coin
}

public fun recover_coins<CoinType>(
    obj: &mut InitiateObject<CoinType>,
    mut sent: vector<Receiving<Coin<CoinType>>>,
    clock: &Clock,
    _ctx: &mut TxContext,
) {
    assert!(
        obj.created_at + obj.deadline < clock::timestamp_ms(clock) as u256,
        EDeadlineNotYetExpired,
    );
    assert!(sent.length() > 0, EInvalidCoins);
    let mut coins = vector::empty<Coin<CoinType>>();
    let len = vector::length(&sent);
    let mut i = 0;
    while (i < len) {
        let coin = transfer::public_receive(&mut obj.id, vector::pop_back(&mut sent));
        vector::push_back(&mut coins, coin);
        i = i + 1;
    };
    sui::pay::join_vec_and_transfer(coins, obj.initiator);
}

fun safe_params<CoinType>(
    initiator: address,
    redeemer: address,
    amount: u64,
    timelock: u256,
    secret_hash: vector<u8>,
    deadline: u256,
    reg_id: address,
    reg: &AtomicSwap::OrdersRegistry<CoinType>,
    ctx: &TxContext,
) {
    assert!(amount > 0, EZeroAmount);
    assert!(timelock > 0, EZeroTimelock);
    assert!(vector::length(&secret_hash) == 32, EInvalidSecretHashLength);
    assert!(deadline > 0 && deadline < 7200000, EZeroDeadline);
    assert!(timelock > 0 && timelock < 604800001, EInvalidTimelock);
    assert!(initiator != redeemer, ESameInitiatorRedeemer);
    assert!(initiator != @0x0, EZeroAddressInitiator);
    assert!(redeemer != @0x0, EZeroAddressRedeemer);
    assert!(tx_context::sender(ctx) != redeemer, ESameFunderRedeemer);
    let order_id = AtomicSwap::create_order_id(
        secret_hash,
        initiator,
        redeemer,
        timelock,
        amount,
        reg_id,
    );
    assert!(!AtomicSwap::does_order_exist<CoinType>(reg, order_id), EDuplicateOrder);
}

#[test_only]
public fun create_admin_cap(ctx: &mut TxContext): AdminCap {
    AdminCap {
        id: object::new(ctx),
    }
}

#[test_only]
public fun create_registry_mapping(ctx: &mut TxContext): RegistryMapping {
    RegistryMapping {
        id: object::new(ctx),
        table: table::new(ctx),
    }
}

#[test_only]
public fun get_uda_id<CoinType>(obj: &InitiateObject<CoinType>): address {
    object::uid_to_address(&obj.id)
}

#[test_only]
public fun init_for_testing(ctx: &mut TxContext) {
    let admin = AdminCap {
        id: object::new(ctx),
    };
    transfer::public_transfer(admin, tx_context::sender(ctx));
    let valid_registry = RegistryMapping {
        id: object::new(ctx),
        table: table::new(ctx),
    };
    let registry_id = object::uid_to_address(&valid_registry.id);
    transfer::share_object(valid_registry);
    event::emit(TableMapping {
        mapping_id: registry_id,
    });
}
