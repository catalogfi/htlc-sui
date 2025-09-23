#[allow(unused_use, duplicate_alias, unused_const, unused_variable)]
#[test_only]
module atomic_swapv1::UDATests;

use 0x1::hash as hash_lib;
use atomic_swapv1::AtomicSwap::{Self, OrdersRegistry};
use atomic_swapv1::UDA::{Self, AdminCap, InitiateObject, RegistryMapping};
use std::vector;
use sui::address;
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin, TreasuryCap};
use sui::hash::blake2b256;
use sui::object::{Self, UID};
use sui::sui::{Self, SUI};
use sui::table;
use sui::test_scenario::{Self as ts, Scenario, receiving_ticket_by_id};
use sui::transfer::{Self, Receiving, make_receiver, receiving_id};

// Test addresses
const ADMIN: address = @0xAD;
const INITIATOR: address = @0xA1;
const REDEEMER: address = @0xA2;
const FUNDER: address = @0xA3;

// Test constants
const SWAP_AMOUNT: u64 = 1000;
const TIMELOCK: u256 = 7200000; // 2 hours in milliseconds
const DEADLINE: u256 = 3600000; // 1 hour in milliseconds

// Setup function that creates a test environment
fun setup(): Scenario {
    let mut scenario = ts::begin(ADMIN);

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Initialize UDA module using test-only init function
        UDA::init_for_testing(ts::ctx(&mut scenario));

        // Create registry for SUI coins
        AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut order_reg = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let (order_reg_address, _) = AtomicSwap::get_order_reg_address<SUI>(&mut order_reg);

        UDA::add_reg_id<SUI>(
            &mut admin_cap,
            &mut registry_mapping,
            order_reg_address,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, admin_cap);
        ts::return_shared(registry_mapping);
        ts::return_shared(order_reg);
    };
    scenario
}

// Helper to create test coins
fun mint_coins(amount: u64, ctx: &mut tx_context::TxContext): Coin<SUI> {
    coin::mint_for_testing<SUI>(amount as u64, ctx)
}

// Helper to generate a test secret and hash
fun generate_secret(): (vector<u8>, vector<u8>) {
    let secret = b"thisisasecretphrase12345";
    let secret_hash = hash_lib::sha2_256(secret);
    (secret, secret_hash)
}

// Helper to generate mock ED25519 keypair
fun generate_keypair(): (vector<u8>, address, vector<u8>, address) {
    let _initiator_sk = x"9bf49a6a0755f953811fce125f2683d50429c3bb49e074147e0089a52eae155f";
    let initiator_pk = x"b9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200";

    let _redeemer_sk = x"c5e26f9b31288c268c31217de8d2a783eec7647c2b8de48286f0a25a2dd6594b";
    let redeemer_pk = x"f1a756ceb2955f680ab622c9c271aa437a22aa978c34ae456f24400d6ea7ccdd";

    let initiator_address = generate_address(initiator_pk);
    let redeemer_address = generate_address(redeemer_pk);

    (initiator_pk, initiator_address, redeemer_pk, redeemer_address)
}

fun generate_address(pubk: vector<u8>): address {
    let flag: u8 = 0; // 0x00 = ED25519, 0x01 = Secp256k1, 0x02 = Secp256r1, 0x03 = multiSig
    let mut preimage = vector::empty<u8>();
    vector::push_back(&mut preimage, flag);
    vector::append(&mut preimage, pubk);
    let add = blake2b256(&preimage);
    address::from_bytes(add)
}

// Common initialization function for tests
fun create_test_uda_object(
    scenario: &mut Scenario,
    clock: &Clock,
    initiator_address: address,
    redeemer_address: address,
    amount: u64,
    timelock: u256,
    deadline: u256,
): address {
    let (_, secret_hash) = generate_secret();

    ts::next_tx(scenario, ADMIN);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(scenario);

        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            amount,
            timelock,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            deadline,
            clock,
            ts::ctx(scenario),
        );

        ts::return_shared<RegistryMapping>(registry_mapping);
        ts::return_shared(registry);
    };

    let uda_id;
    ts::next_tx(scenario, ADMIN);
    {
        // Get the UDA object ID from the shared objects
        let uda_obj = ts::take_shared<InitiateObject<SUI>>(scenario);
        uda_id = UDA::get_uda_id(&uda_obj);
        ts::return_shared(uda_obj);
    };

    uda_id
}

// Test module initialization
#[test]
fun test_uda_init() {
    let mut scenario = setup();

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Verify AdminCap was created
        let _admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        ts::return_to_sender(&scenario, _admin_cap);

        // Verify RegistryMapping was created
        let _registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        ts::return_shared<RegistryMapping>(_registry_mapping);
    };

    ts::end(scenario);
}

// Test successful UDA object creation
#[test]
fun test_uda_create_object() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero amount validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAmount)]
fun test_uda_revert_create_object_zero_amount() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to zero amount
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            0, // Zero amount
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero timelock validation
#[test]
#[expected_failure(abort_code = UDA::EInvalidTimelock)]
fun test_uda_revert_create_object_zero_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to zero timelock
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            0, // Zero timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = UDA::EInvalidTimelock)]
fun test_uda_revert_create_object_large_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to large timelock
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800000 + 1, // Large timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test invalid secret hash length
#[test]
#[expected_failure(abort_code = UDA::EInvalidSecretHashLength)]
fun test_uda_revert_create_object_invalid_secret_hash_length() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to invalid secret hash length
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            x"1234", // Invalid length
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero deadline validation
#[test]
#[expected_failure(abort_code = UDA::EInvalidDeadline)]
fun test_uda_revert_create_object_small_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to small deadline
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE - 1, // Small deadline
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test deadline >= 7 days
#[test]
#[expected_failure(abort_code = UDA::EInvalidDeadline)]
fun test_uda_revert_create_object_big_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to deadline >= 2 hours
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            604800001, // >= 7 days deadline
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test timelock >= 7 days validation
#[test]
#[expected_failure(abort_code = UDA::EInvalidTimelock)]
fun test_uda_revert_create_object_big_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to timelock >= 7 days
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800001, // >7 days timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test same initiator and redeemer validation
#[test]
#[expected_failure(abort_code = UDA::ESameInitiatorRedeemer)]
fun test_uda_revert_create_object_same_initiator_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail since initiator and redeemer are the same
        UDA::create_object<SUI>(
            initiator_address,
            initiator_address, // Same as initiator
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero address initiator validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAddressInitiator)]
fun test_uda_revert_create_object_zero_address_initiator() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, _initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to zero address initiator
        UDA::create_object<SUI>(
            @0x0, // Zero address
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero address redeemer validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAddressRedeemer)]
fun test_uda_revert_create_object_zero_address_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail due to zero address redeemer
        UDA::create_object<SUI>(
            initiator_address,
            @0x0, // Zero address
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test same funder and redeemer validation
#[test]
#[expected_failure(abort_code = UDA::ESameFunderRedeemer)]
fun test_uda_revert_create_object_same_funder_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Try to create object with redeemer as the sender (should fail)
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail since funder and redeemer are the same
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry_mapping);
        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test registry mapping functionality
#[test]
fun test_uda_add_and_get_reg_id() {
    let mut scenario = setup();

    let initial_registry_address;
    let new_registry_address;
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);

        initial_registry_address = UDA::get_reg_id<SUI>(&registry_mapping);
        // Create a new registry for testing
        let new_registry_id = AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
        new_registry_address = object::id_to_address(&new_registry_id);

        assert!(initial_registry_address != new_registry_address, 0);

        // Add the registry mapping
        UDA::add_reg_id<SUI>(
            &mut admin_cap,
            &mut registry_mapping,
            new_registry_address,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, admin_cap);
        ts::return_shared<RegistryMapping>(registry_mapping);
    };

    let retrieved_reg_address;
    ts::next_tx(&mut scenario, ADMIN);
    {
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        // Get the registry ID back
        let retrieved_reg_address = UDA::get_reg_id<SUI>(&registry_mapping);
        assert!(retrieved_reg_address != initial_registry_address, 0);
        assert!(retrieved_reg_address == new_registry_address, 0);
        ts::return_shared<RegistryMapping>(registry_mapping);
    };

    ts::end(scenario);
}

fun fund_uda(amount: u64, scenario: &mut Scenario, uda_id: address): ID {
    let mint_coins_id;
    ts::next_tx(scenario, FUNDER);
    {
        let mint_coins = mint_coins(amount, ts::ctx(scenario));
        mint_coins_id = object::id(&mint_coins);
        transfer::public_transfer(mint_coins, uda_id);
    };
    ts::next_tx(scenario, FUNDER);
    {
        let minted_coins = ts::take_from_address<Coin<SUI>>(scenario, uda_id);
        assert!(coin::value(&minted_coins) == amount, 0);
        ts::return_to_address(uda_id, minted_coins);
    };
    mint_coins_id
}

// Test successful UDA initialization
#[test]
fun test_uda_initialize() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        UDA::initialize<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coin),
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    let effect = ts::next_tx(&mut scenario, ADMIN);
    // 1: Initialized 2: Initiated
    assert!(effect.num_user_events() == 2, 0);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful coin recovery after deadline
#[test]
fun test_uda_recover_coins_not_initialized() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    // Advance time past deadline
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1000) as u64);
    };
    ts::next_tx(&mut scenario, ADMIN);

    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let coins_to_recover = ts::take_from_address<Coin<SUI>>(&scenario, uda_id);
        let coins_to_recover_id = object::id(&coins_to_recover);
        let receiving_coins_to_recover = ts::receiving_ticket_by_id<Coin<SUI>>(coins_to_recover_id);
        ts::return_to_address(uda_id, coins_to_recover);
        UDA::recover_coins<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coins_to_recover),
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
    };

    ts::next_tx(&mut scenario, initiator_address);
    {
        let coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful coin recovery after deadline
#[test]
fun test_uda_automatic_recovery_after_initializing() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT*2, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        let sent = vector::singleton<Receiving<Coin<SUI>>>(receiving_coin);
        UDA::initialize<SUI>(
            &mut uda_obj,
            sent,
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    let effects = ts::next_tx(&mut scenario, ADMIN);
    assert!(effects.num_user_events() == 2, 0);

    ts::next_tx(&mut scenario, initiator_address);
    {
        let coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful coin recovery after deadline
#[test]
fun test_uda_send_and_recover_coins_after_initializing() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        let sent = vector::singleton<Receiving<Coin<SUI>>>(receiving_coin);
        UDA::initialize<SUI>(
            &mut uda_obj,
            sent,
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    let effects = ts::next_tx(&mut scenario, ADMIN);
    assert!(effects.num_user_events() == 2, 0);

    ts::next_tx(&mut scenario, initiator_address);
    {
        let coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&coins) == 0, 0);
        ts::return_to_sender(&scenario, coins);
    };

    // Add extra coins to the UDA
    let test_coins: u64 = 12345;
    fund_uda(test_coins, &mut scenario, uda_id);

    // Advance time past deadline
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1000) as u64);
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let coins_to_recover = ts::take_from_address<Coin<SUI>>(&scenario, uda_id);
        let coins_to_recover_id = object::id(&coins_to_recover);
        let receiving_coins_to_recover = ts::receiving_ticket_by_id<Coin<SUI>>(coins_to_recover_id);
        ts::return_to_address(uda_id, coins_to_recover);
        UDA::recover_coins<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coins_to_recover),
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
    };

    ts::next_tx(&mut scenario, initiator_address);
    {
        let coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&coins) == test_coins, 0);
        ts::return_to_sender(&scenario, coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to initialize with zero coins
#[test]
#[expected_failure(abort_code = UDA::EInvalidCoins)]
fun test_uda_revert_initialize_zero_coins() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        UDA::initialize<SUI>(
            &mut uda_obj,
            vector::empty<Receiving<Coin<SUI>>>(),
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to initialize with insufficient funds
#[test]
#[expected_failure(abort_code = UDA::EInsufficientFunds)]
fun test_uda_revert_initialize_insufficient_funds() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT-1, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        UDA::initialize<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coin),
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to recover coins before deadline
#[test]
#[expected_failure(abort_code = UDA::EDeadlineNotYetExpired)]
fun test_uda_revert_recover_coins_before_deadline() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    // Advance time past deadline
    ts::next_tx(&mut scenario, ADMIN);
    {
        clock::increment_for_testing(&mut clock, (DEADLINE - 1000) as u64);
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        UDA::recover_coins<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coin),
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to recover coins with zero coins
#[test]
#[expected_failure(abort_code = UDA::EInvalidCoins)]
fun test_uda_revert_recover_coins_zero_coins() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    // Advance time past deadline
    ts::next_tx(&mut scenario, ADMIN);
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1) as u64);
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        UDA::recover_coins<SUI>(
            &mut uda_obj,
            vector::empty<Receiving<Coin<SUI>>>(),
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful initialization with multiple coins
#[test]
fun test_uda_initialize_multiple_coins() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id1 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);
    let mint_coins_id2 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin1 = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id1);
        let receiving_coin2 = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id2);
        let mut sent = vector::singleton<Receiving<Coin<SUI>>>(receiving_coin1);
        vector::push_back(&mut sent, receiving_coin2);
        UDA::initialize<SUI>(
            &mut uda_obj,
            sent,
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    let effects = ts::next_tx(&mut scenario, ADMIN);
    assert!(effects.num_user_events() == 2, 0);

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful recovery with multiple coins
#[test]
fun test_uda_recover_coins_multiple_coins_not_initialized() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id1 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);
    let mint_coins_id2 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);

    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1) as u64);
    };

    ts::next_tx(&mut scenario, ADMIN);

    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut coins_to_recover = ts::ids_for_address<Coin<SUI>>(uda_id);
        assert!(vector::length(&coins_to_recover) == 2, 0);
        let mut sent = vector::empty<Receiving<Coin<SUI>>>();
        while (vector::length(&coins_to_recover) > 0) {
            let coin = ts::take_from_address_by_id<Coin<SUI>>(
                &scenario,
                uda_id,
                vector::pop_back(&mut coins_to_recover),
            );
            let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(object::id(&coin));
            vector::push_back(&mut sent, receiving_coin);
            ts::return_to_address(uda_id, coin);
        };
        UDA::recover_coins<SUI>(
            &mut uda_obj,
            sent,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
    };

    ts::next_tx(&mut scenario, initiator_address);
    {
        let coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to create duplicate order
#[test]
#[expected_failure(abort_code = UDA::EDuplicateOrder)]
fun test_uda_revert_create_object_duplicate_order() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);
        UDA::initialize<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coin),
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    // Try to create second UDA object with same parameters (should fail due to duplicate order)
    let uda_id2 = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to use wrong registry
#[test]
#[expected_failure(abort_code = UDA::EInvalidRegistry)]
fun test_uda_revert_create_uda_wrong_registry() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Create a different registry to use (this should cause EInvalidRegistry)
        AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
    };

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to use wrong registry
#[test]
#[expected_failure(abort_code = UDA::EInvalidRegistry)]
fun test_uda_revert_initialize_wrong_registry() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = create_test_uda_object(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    let mint_coins_id = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Create a different registry to use (this should cause EInvalidRegistry)
        AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id);

        let mut wrong_registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        UDA::initialize<SUI>(
            &mut uda_obj,
            vector::singleton<Receiving<Coin<SUI>>>(receiving_coin),
            &mut wrong_registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(wrong_registry);
        ts::return_shared(registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Full flow test: UDA created, UDA funded (multi coin), UDA initialized -> Order created + Excess automatically recovered, Order redeemeed
#[test]
fun test_uda_complete_flow() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let (secret, secret_hash) = generate_secret();

    let order_id;
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            &mut registry,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );
        
        ts::return_shared<RegistryMapping>(registry_mapping);
        ts::return_shared(registry);
    };

    let uda_id;
    ts::next_tx(&mut scenario, ADMIN);
    {
        // Get the UDA object ID from the shared objects
        let uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        uda_id = UDA::get_uda_id(&uda_obj);
        ts::return_shared(uda_obj);
    };

    let mint_coins_id1 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);
    let mint_coins_id2 = fund_uda(SWAP_AMOUNT, &mut scenario, uda_id);
    let mint_coins_id3 = fund_uda(SWAP_AMOUNT/2, &mut scenario, uda_id);

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut uda_obj = ts::take_shared<InitiateObject<SUI>>(&scenario);
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let registry_mapping = ts::take_shared<RegistryMapping>(&scenario);
        let receiving_coin1 = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id1);
        let receiving_coin2 = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id2);
        let receiving_coin3 = ts::receiving_ticket_by_id<Coin<SUI>>(mint_coins_id3);
        let mut sent = vector::singleton<Receiving<Coin<SUI>>>(receiving_coin1);
        vector::push_back(&mut sent, receiving_coin2);
        vector::push_back(&mut sent, receiving_coin3);
        UDA::initialize<SUI>(
            &mut uda_obj,
            sent,
            &mut registry,
            &clock,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(uda_obj);
        ts::return_shared(registry);
        ts::return_shared(registry_mapping);
    };

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let order_id = AtomicSwap::generate_order_id(
            secret_hash,
            initiator_address,
            redeemer_address,
            TIMELOCK,
            SWAP_AMOUNT,
            &registry,
        );
        AtomicSwap::redeem<SUI>(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
        );
        ts::return_shared(registry);
    };

    let effects = ts::next_tx(&mut scenario, redeemer_address);
    assert!(effects.num_user_events() == 1, 0);
    {
        let redeemed_bal = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&redeemed_bal) == SWAP_AMOUNT, 0);
        ts::return_to_sender<Coin<SUI>>(&scenario, redeemed_bal);
    };

    ts::next_tx(&mut scenario, initiator_address);
    {
        let recovered_bal = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&recovered_bal) == SWAP_AMOUNT, 0);
        ts::return_to_sender<Coin<SUI>>(&scenario, recovered_bal);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}
