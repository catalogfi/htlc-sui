#[allow(unused_use)]
#[test_only]
module atomic_swapv1::AtomicSwapTests;

use 0x1::hash as hash_lib;
use atomic_swapv1::AtomicSwap::{Self, OrdersRegistry};
use sui::address;
use sui::clock::{Self, Clock};
use sui::coin::{Self, Coin, TreasuryCap};
use sui::hash::blake2b256;
use sui::sui::{Self, SUI};
use sui::test_scenario::{Self as ts, Scenario};

// Test addresses
const ADMIN: address = @0xAD;
const INITIATOR: address = @0xA1;
const REDEEMER: address = @0xA2;
// Test constants
const SWAP_AMOUNT: u64 = 1000;
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
    let address = address::from_bytes(add);
    address
}

// Common initialization function for tests
fun initialize_test_swap(
    scenario: &mut Scenario,
    clock: &Clock,
    initiator_address: address,
    redeemer_pubk: vector<u8>,
    amount: u64,
    timelock: u256,
): vector<u8> {
    let (_, secret_hash) = generate_secret();
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
            ts::ctx(scenario),
        );

        ts::return_shared(registry);
    };

    // Return order ID for further operations
    AtomicSwap::generate_order_id(
        secret_hash,
        initiator_address,
        generate_address(redeemer_pubk),
        timelock,
    )
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
            ts::ctx(&mut scenario),
        );

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

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem_swap(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
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

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    ts::next_tx(&mut scenario, initiator_address);
    {
        // Check that INITIATOR received the coins back
        let refunded_bal = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&refunded_bal) == SWAP_AMOUNT, 0);
        ts::return_to_sender<Coin<SUI>>(&scenario, refunded_bal);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to redeem with incorrect secret
#[test]
#[expected_failure(abort_code = AtomicSwap::EIncorrectSecret)]
fun test_revert_redeem_with_incorrect_secret() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to refund before timelock expires
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderNotExpired)]
fun test_revert_refund_before_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );
    // Try to refund before timelock expires (should fail)
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail since timelock hasn't expired
        AtomicSwap::refund_swap(
            &mut registry,
            order_id,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test duplicate order creation
#[test]
#[expected_failure(abort_code = AtomicSwap::EDuplicateOrder)]
fun test_revert_init_duplicate_order() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    let _order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );
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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EDuplicateOrder)]
fun test_revert_init_on_behalf_duplicate_order() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    let _order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );
    // Try to create a duplicate with same secret and initiator
    let (_, secret_hash) = generate_secret();

    // Mint more coins for the second attempt
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, ADMIN);
    };

    // Try to create a duplicate (should fail)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to duplicate order_id
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            redeemer_pk,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to redeem an already fulfilled order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderFulfilled)]
fun test_revert_redeem_already_fulfilled() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem_swap(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test that same initiator and redeemer is rejected
#[test]
#[expected_failure(abort_code = AtomicSwap::ESameInitiatorRedeemer)]
fun test_revert_init_same_initiator_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, ADMIN);
    };

    // Try to create a swap with same initiator and redeemer (should fail)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail since initiator and redeemer are the same
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            initiator_pk,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test that same initiator and redeemer is rejected
#[test]
#[expected_failure(abort_code = AtomicSwap::ESameInitiatorRedeemer)]
fun test_revert_init_on_behalf_same_initiator_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to refund an already fulfilled order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderFulfilled)]
fun test_revert_refund_already_fulfilled() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem_swap(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero timelock
#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroTimelock)]
fun test_revert_init_zero_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroTimelock)]
fun test_revert_init_on_behalf_zero_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, ADMIN);
    };

    // Try to create a swap with zero timelock (should fail)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to zero timelock
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            redeemer_pk,
            secret_hash,
            SWAP_AMOUNT,
            0, // Zero timelock
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidSecretHashLength)]
fun test_revert_init_on_behalf_invalid_secret_hash_length() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, _secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, ADMIN);
    };

    // Try to create a swap with zero timelock (should fail)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to zero timelock
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            redeemer_pk,
            x"1234",
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidSecretHashLength)]
fun test_revert_init_invalid_secret_hash_length() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, _secret_hash) = generate_secret();
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
            x"1234",
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero amount
#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroAmount)]
fun test_revert_init_swap_zero_amount() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroAmount)]
fun test_revert_init_on_behalf_zero_amount() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, ADMIN);
    };

    // Try to create a swap with zero amount (should fail)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to zero amount
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            redeemer_pk,
            secret_hash,
            0, // Zero amount
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroAddressInitiator)]
fun test_revert_init_on_behalf_zero_initiator() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            address::from_bytes(
                x"0000000000000000000000000000000000000000000000000000000000000000",
            ),
            redeemer_pk,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test insufficient balance
#[test]
#[expected_failure(abort_code = AtomicSwap::EIncorrectFunds)]
fun test_revert_init_swap_insufficient_balance() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test insufficient balance
#[test]
#[expected_failure(abort_code = AtomicSwap::EIncorrectFunds)]
fun test_revert_init_on_behalf_insufficient_balance() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

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
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator_address,
            redeemer_pk,
            secret_hash,
            SWAP_AMOUNT, // Amount greater than available coins
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test insufficient balance
#[test]
#[expected_failure(abort_code = AtomicSwap::ESameFunderRedeemer)]
fun test_revert_init_on_behalf_same_funder_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_funder_pk, funder_address, _redeemer_pk, _redeemer_address) = generate_keypair();
    // Mint coins to the initiator (less than swap amount)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT / 2, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, funder_address);
    };

    ts::next_tx(&mut scenario, funder_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        let initiator: address = @0xFF;
        // This should fail due to same funder and redeemer
        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator,
            _funder_pk,
            secret_hash,
            SWAP_AMOUNT, // Amount greater than available coins
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
fun test_init_on_behalf() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (secret, secret_hash) = generate_secret();
    let (_funder_pk, funder_address, redeemer_pk, redeemer_address) = generate_keypair();
    let initiator: address = @0xFF;

    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, funder_address);
    };

    ts::next_tx(&mut scenario, funder_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        AtomicSwap::initiate_on_behalf(
            &mut registry,
            initiator,
            redeemer_pk,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let order_id = AtomicSwap::generate_order_id(
            secret_hash,
            initiator,
            redeemer_address,
            TIMELOCK,
        );
        AtomicSwap::redeem_swap(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
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

// Test attempting to redeem non-existent order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderNotInitiated)]
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
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test attempting to refund non-existent order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderNotInitiated)]
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
            ts::ctx(&mut scenario),
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

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Perform instant refund
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        let registry_addr = object::uid_to_address(reg_id);
        let _refund_digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);

        // Generated using fastcrypto-cli
        let refund_signature =
            x"9e8f581d93e52a288778c104fa22fabd8fa414a0206bbfcc685a8f8084d801e291e15ee0938d8ab88d91b45924a69065b4bfc49ef92cc3641706c714c420f208";

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
            refund_signature,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    // Check that initiator received the coins back
    ts::next_tx(&mut scenario, initiator_address);
    {
        let refunded_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&refunded_coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, refunded_coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
fun test_instant_refund_redeemer_called() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Perform instant refund
    ts::next_tx(&mut scenario, _redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        let registry_addr = object::uid_to_address(reg_id);
        let _refund_digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);

        // Generated using fastcrypto-cli
        let refund_signature =
            x"9e8f581d93e52a288778c104fa22fabd8fa414a0206bbfcc685a8f8084d801e291e15ee0938d8ab88d91b45924a69065b4bfc49ef92cc3641706c714c420f208";

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
            refund_signature,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    // Check that initiator received the coins back
    ts::next_tx(&mut scenario, initiator_address);
    {
        let refunded_coins = ts::take_from_sender<Coin<SUI>>(&scenario);
        assert!(coin::value(&refunded_coins) == SWAP_AMOUNT, 0);
        ts::return_to_sender(&scenario, refunded_coins);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test invalid signature for instant refund
#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidSignature)]
fun test_revert_instant_refund_invalid_signature() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Generate an invalid refund signature
    let invalid_refund_signature =
        x"0fc727690a97bb47058e36156646f0129977697607b7d8bc605bcd3e516d14280b841cfea6a5ee72863604de5602c8e1ad75c4fb7efb2e7d2e2b5f7658b46e0e";

    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
            invalid_refund_signature,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test instant refund on already fulfilled order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderFulfilled)]
fun test_revert_instant_refund_already_fulfilled() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_pk,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem_swap(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    // Generate the refund signature
    let refund_signature =
        x"bb814078fd2dfbe03cdde1e83dcd93b54b35a33781cf1bb4c1c1209c1954fa025ce2e129945cbf1ac12ad1e4b8a6ce082771387370c15151df4f704c3ed82f0e";

    // Try to perform instant refund on already fulfilled order (should fail)
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
            refund_signature,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test instant refund on non-existent order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderNotInitiated)]
fun test_revert_instant_refund_nonexistent_order() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    // Generate fake order ID
    let fake_order_id = b"non_existent_order_id";

    // Generate the refund signature
    let refund_signature =
        x"bb814078fd2dfbe03cdde1e83dcd93b54b35a33781cf1bb4c1c1209c1954fa025ce2e129945cbf1ac12ad1e4b8a6ce082771387370c15151df4f704c3ed82f0e";

    // Try to perform instant refund on non-existent order (should fail)
    ts::next_tx(&mut scenario, INITIATOR);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::instant_refund(
            &mut registry,
            fake_order_id,
            refund_signature,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidPubkey)]
fun test_revert_invalid_public_key_length() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    let _order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        x"0121",
        SWAP_AMOUNT,
        TIMELOCK,
    );

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

//Making sure that Order CoinType is atomic with the OrderRegistry CoinType. This should throw a compilation error as the registry and the order are of different CoinTypes
// #[test]
// #[expected_failure]
// fun test_revert_init_with_different_coin(){
//     let mut scenario = setup();
//     let clock = clock::create_for_testing(ts::ctx(&mut scenario));

//     let (_, secret_hash) = generate_secret();
//     let (__initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

//     // Create MYCOIN currency and mint all coins to ADMIN
//     ts::next_tx(&mut scenario, ADMIN);
//     {
//         createCoin(MY_COIN {}, ts::ctx(&mut scenario));
//     };

//     // Mint MYCOIN to the initiator
//     ts::next_tx(&mut scenario, ADMIN);
//     {
//         let mut admin_coins = ts::take_from_sender<Coin<MY_COIN>>(&scenario);
//         let transfer_coins = coin::split(&mut admin_coins, SWAP_AMOUNT as u64, ts::ctx(&mut scenario));
//         transfer::public_transfer(transfer_coins, initiator_address);
//         ts::return_to_sender(&scenario, admin_coins);
//     };

//     // Initiate a swap
//     ts::next_tx(&mut scenario, initiator_address);
//     {
//         let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
//         let init_coins = ts::take_from_sender<Coin<MY_COIN>>(&scenario);

//         AtomicSwap::initiate(
//             &mut registry,
//             redeemer_pk,
//             secret_hash,
//             SWAP_AMOUNT,
//             TIMELOCK,
//             init_coins,
//             &clock,
//             ts::ctx(&mut scenario)
//         );

//         ts::return_shared(registry);
//     };

//     clock::destroy_for_testing(clock);
//     ts::end(scenario);
// }

// public struct MY_COIN has drop {}

// fun createCoin(witness: MY_COIN, ctx: &mut TxContext) {
//     let (mut treasury, metadata) = coin::create_currency(
//         witness,
//         6,
//         b"MYCOIN",
//         b"",
//         b"",
//         option::none(),
//         ctx,
//     );
//     transfer::public_freeze_object(metadata);
//     coin::mint_and_transfer(&mut treasury, 1000000000000, tx_context::sender(ctx), ctx);
//     transfer::public_transfer(treasury, tx_context::sender(ctx))
// }
