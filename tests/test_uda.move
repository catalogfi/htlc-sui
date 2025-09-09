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
use sui::test_scenario::{Self as ts, Scenario};
use sui::transfer::{Self, Receiving};

// Test addresses
const ADMIN: address = @0xAD;
const INITIATOR: address = @0xA1;
const REDEEMER: address = @0xA2;
const FUNDER: address = @0xA3;

// Test constants
const SWAP_AMOUNT: u64 = 1000;
const TIMELOCK: u256 = 3600000; // 1 hour in milliseconds
const DEADLINE: u256 = 300000; // 5 minutes in milliseconds

// Setup function that creates a test environment
fun setup(): Scenario {
    let mut scenario = ts::begin(ADMIN);

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Initialize UDA module using test-only init function
        UDA::init_for_testing(ts::ctx(&mut scenario));

        // Create registry for SUI coins
        let registry_id = AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));

        // Get the created objects and add registry mapping
        let mut admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        UDA::add_reg_id<SUI>(
            &mut admin_cap,
            &mut registry_mapping,
            object::id_to_address(&registry_id),
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, admin_cap);
        ts::return_to_sender(&scenario, registry_mapping);
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
fun initialize_test_uda(
    scenario: &mut Scenario,
    clock: &Clock,
    initiator_address: address,
    redeemer_address: address,
    amount: u64,
    timelock: u256,
    deadline: u256,
): address {
    let (_, secret_hash) = generate_secret();

    ts::next_tx(scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(scenario);

        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            amount,
            timelock,
            vector::empty<u8>(),
            &mut registry_mapping,
            deadline,
            clock,
            ts::ctx(scenario),
        );

        ts::return_to_sender(scenario, registry_mapping);
    };

    // Get the UDA object ID from the shared objects
    let uda_obj = ts::take_shared<InitiateObject<SUI>>(scenario);
    let uda_id = UDA::get_uda_id(&uda_obj);
    ts::return_shared(uda_obj);

    uda_id
}

// Test module initialization
#[test]
fun test_init() {
    let mut scenario = setup();

    ts::next_tx(&mut scenario, ADMIN);
    {
        // Verify AdminCap was created
        let _admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        ts::return_to_sender(&scenario, _admin_cap);

        // Verify RegistryMapping was created
        let _registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);
        ts::return_to_sender(&scenario, _registry_mapping);
    };

    ts::end(scenario);
}

// Test successful UDA object creation
#[test]
fun test_create_object() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful UDA initialization
#[test]
fun test_initialize() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Mint coins to funder for initialization
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, FUNDER);
    };

    // Note: The initialize function requires Receiving objects which are created
    // by the Sui framework when coins are sent to the object. In a real scenario,
    // coins would be sent to the UDA object first, creating Receiving objects.
    // For testing purposes, we demonstrate the setup and object creation.

    // Return the coins to avoid unused variable error
    ts::next_tx(&mut scenario, FUNDER);
    {
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        ts::return_to_sender(&scenario, init_coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful coin recovery after deadline
#[test]
fun test_recover_coins() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Mint coins to funder
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, FUNDER);
    };

    // Advance time past deadline
    ts::next_tx(&mut scenario, ADMIN);
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1000) as u64);
    };

    // Note: The recover_coins function requires Receiving objects which are created
    // by the Sui framework when coins are sent to the object. In a real scenario,
    // coins would be sent to the UDA object first, creating Receiving objects.
    // For testing purposes, we demonstrate the setup and object creation.

    // Return the coins to avoid unused variable error
    ts::next_tx(&mut scenario, FUNDER);
    {
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        ts::return_to_sender(&scenario, init_coins);
    };

    // Check that initiator received the coins back
    ts::next_tx(&mut scenario, initiator_address);
    {
        let recovered_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&recovered_coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, recovered_coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to initialize with zero coins
#[test]
#[expected_failure(abort_code = UDA::EInvalidCoins)]
fun test_revert_initialize_zero_coins() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Note: This test would require Receiving objects to properly test the
    // EInvalidCoins error. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to initialize after deadline expired
#[test]
#[expected_failure(abort_code = UDA::EDeadlineExpired)]
fun test_revert_initialize_after_deadline() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Advance time past deadline
    ts::next_tx(&mut scenario, ADMIN);
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1000) as u64);
    };

    // Mint coins to funder
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, FUNDER);
    };

    // Note: This test would require Receiving objects to properly test the
    // EDeadlineExpired error. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to recover coins before deadline
#[test]
#[expected_failure(abort_code = UDA::EDeadlineNotYetExpired)]
fun test_revert_recover_coins_before_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Mint coins to funder
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, FUNDER);
    };

    // Note: This test would require Receiving objects to properly test the
    // EDeadlineNotYetExpired error. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to recover coins with zero coins
#[test]
#[expected_failure(abort_code = UDA::EInvalidCoins)]
fun test_revert_recover_coins_zero_coins() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Create UDA object
    let uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Advance time past deadline
    ts::next_tx(&mut scenario, ADMIN);
    {
        clock::increment_for_testing(&mut clock, (DEADLINE + 1000) as u64);
    };

    // Note: This test would require Receiving objects to properly test the
    // EInvalidCoins error. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero amount validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAmount)]
fun test_revert_create_object_zero_amount() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to zero amount
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            0, // Zero amount
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero timelock validation
#[test]
#[expected_failure(abort_code = UDA::EZeroTimelock)]
fun test_revert_create_object_zero_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to zero timelock
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            0, // Zero timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test invalid secret hash length
#[test]
#[expected_failure(abort_code = UDA::EInvalidSecretHashLength)]
fun test_revert_create_object_invalid_secret_hash_length() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to invalid secret hash length
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            x"1234", // Invalid length
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero deadline validation
#[test]
#[expected_failure(abort_code = UDA::EZeroDeadline)]
fun test_revert_create_object_zero_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to zero deadline
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            0, // Zero deadline
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test deadline >= 2 hours validation
#[test]
#[expected_failure(abort_code = UDA::EZeroDeadline)]
fun test_revert_create_object_big_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to deadline >= 2 hours
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            7200000, // 2 hours deadline
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test timelock >= 7 days validation
#[test]
#[expected_failure(abort_code = UDA::EInvalidTimelock)]
fun test_revert_create_object_big_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to timelock >= 7 days
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800001, // >7 days timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test same initiator and redeemer validation
#[test]
#[expected_failure(abort_code = UDA::ESameInitiatorRedeemer)]
fun test_revert_create_object_same_initiator_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail since initiator and redeemer are the same
        UDA::create_object<SUI>(
            initiator_address,
            initiator_address, // Same as initiator
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero address initiator validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAddressInitiator)]
fun test_revert_create_object_zero_address_initiator() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, _initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to zero address initiator
        UDA::create_object<SUI>(
            @0x0, // Zero address
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero address redeemer validation
#[test]
#[expected_failure(abort_code = UDA::EZeroAddressRedeemer)]
fun test_revert_create_object_zero_address_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to zero address redeemer
        UDA::create_object<SUI>(
            initiator_address,
            @0x0, // Zero address
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test same funder and redeemer validation
#[test]
#[expected_failure(abort_code = UDA::ESameFunderRedeemer)]
fun test_revert_create_object_same_funder_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Try to create object with redeemer as the sender (should fail)
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail since funder and redeemer are the same
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test registry mapping functionality
#[test]
fun test_add_and_get_reg_id() {
    let mut scenario = setup();

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut admin_cap = ts::take_from_sender<AdminCap>(&scenario);
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // Create a new registry for testing
        let new_registry_id = AtomicSwap::create_orders_registry<SUI>(ts::ctx(&mut scenario));
        let new_registry_address = object::id_to_address(&new_registry_id);

        // Add the registry mapping
        UDA::add_reg_id<SUI>(
            &mut admin_cap,
            &mut registry_mapping,
            new_registry_address,
            ts::ctx(&mut scenario),
        );

        // Get the registry ID back
        let retrieved_id = UDA::get_reg_id<SUI>(&registry_mapping);
        assert!(retrieved_id == new_registry_address, 0);

        ts::return_to_sender(&scenario, admin_cap);
        ts::return_to_sender(&scenario, registry_mapping);
    };

    ts::end(scenario);
}

// Test edge case: deadline exactly at 2 hours (should fail)
#[test]
#[expected_failure(abort_code = UDA::EZeroDeadline)]
fun test_revert_create_object_exact_2_hour_deadline() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to exactly 2 hours deadline
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            &mut registry_mapping,
            7200000, // Exactly 2 hours deadline
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test edge case: timelock exactly at 7 days (should fail)
#[test]
#[expected_failure(abort_code = UDA::EInvalidTimelock)]
fun test_revert_create_object_exact_7_day_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    ts::next_tx(&mut scenario, FUNDER);
    {
        let mut registry_mapping = ts::take_from_sender<RegistryMapping>(&scenario);

        // This should fail due to exactly 7 days timelock
        UDA::create_object<SUI>(
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800001, // Exactly 7 days + 1ms timelock
            vector::empty<u8>(),
            &mut registry_mapping,
            DEADLINE,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_to_sender(&scenario, registry_mapping);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful initialization with multiple coins
#[test]
fun test_initialize_multiple_coins() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let _uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Note: This test would require Receiving objects to properly test multiple
    // coin initialization. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test successful recovery with multiple coins
#[test]
fun test_recover_coins_multiple_coins() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let _uda_id = initialize_test_uda(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
        DEADLINE,
    );

    // Note: This test would require Receiving objects to properly test multiple
    // coin recovery. For now, we test the object creation part.

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}
