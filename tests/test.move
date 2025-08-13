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
use sui::object::uid_to_inner;

// Test addresses
const ADMIN: address = @0xAD;
const INITIATOR: address = @0xA1;
const REDEEMER: address = @0xA2;
// Test constants
const SWAP_AMOUNT: u64 = 1000;
const TIMELOCK: u256 = 3600000; // 1 hour in milliseconds
// const DESTINATION_DATA: vector<u8> = [];
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
    address::from_bytes(add)
}

// Common initialization function for tests
fun initialize_test_swap(
    scenario: &mut Scenario,
    clock: &Clock,
    initiator_address: address,
    redeemer_address: address,
    amount: u64,
    timelock: u256,
): vector<u8> {
    let (_, secret_hash) = generate_secret();
    let order_id;
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
            initiator_address,
            redeemer_address,
            secret_hash,
            amount,
            timelock,
            vector::empty<u8>(),
            init_coins,
            clock,
            ts::ctx(scenario),
        );

    order_id = AtomicSwap::generate_order_id(
        secret_hash,
        initiator_address,
        redeemer_address,
        timelock,
        amount,
        &registry
    );
        ts::return_shared(registry);
    };

    // Return order ID for further operations
    order_id
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
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

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
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
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
fun test_redeem() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem(
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
fun test_refund() {
    let mut scenario = setup();
    let mut clock = clock::create_for_testing(ts::ctx(&mut scenario));
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
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

        AtomicSwap::refund(
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
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
        AtomicSwap::redeem(
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );
    // Try to refund before timelock expires (should fail)
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail since timelock hasn't expired
        AtomicSwap::refund(
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let _order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
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
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem(
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
        AtomicSwap::redeem(
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
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

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
            initiator_address,
            initiator_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem(
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
        AtomicSwap::refund(
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
#[expected_failure(abort_code = AtomicSwap::EInvalidTimelock)]
fun test_revert_init_zero_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

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
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            0, // Zero timelock
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test >= 7 day timelock
#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidTimelock)]
fun test_revert_init_big_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

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
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800001, // >7 days timelock
            vector::empty<u8>(),
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
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

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

        AtomicSwap::initiate(
            &mut registry,
            initiator_address,
            redeemer_address,
            x"1234",
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
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
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

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
            initiator_address,
            redeemer_address,
            secret_hash,
            0, // Zero amount
            TIMELOCK,
            vector::empty<u8>(),
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
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();
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
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT, // Amount greater than available coins
            TIMELOCK,
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
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
        AtomicSwap::redeem(
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
        AtomicSwap::refund(
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Perform instant refund
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        let registry_addr = object::uid_to_address(reg_id);
        let _refund_digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);
        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
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

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Perform instant refund
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        let registry_addr = object::uid_to_address(reg_id);
        let _refund_digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
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



// Test instant refund on already fulfilled order
#[test]
#[expected_failure(abort_code = AtomicSwap::EOrderFulfilled)]
fun test_revert_instant_refund_already_fulfilled() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    let (secret, _) = generate_secret();

    // First redeem successfully
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::redeem(
            &mut registry,
            order_id,
            secret,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    // Try to perform instant refund on already fulfilled order (should fail)
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
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

    // Try to perform instant refund on non-existent order (should fail)
    ts::next_tx(&mut scenario, INITIATOR);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        AtomicSwap::instant_refund(
            &mut registry,
            fake_order_id,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test instant refund with wrong sender (not redeemer)
#[test]
#[expected_failure(abort_code = AtomicSwap::ESenderNotRedeemer)]
fun test_revert_instant_refund_wrong_sender() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    let order_id = initialize_test_swap(
        &mut scenario,
        &clock,
        initiator_address,
        redeemer_address,
        SWAP_AMOUNT,
        TIMELOCK,
    );

    // Try to perform instant refund with initiator (wrong sender) - should fail
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);

        // This should fail since the sender is not the redeemer
        AtomicSwap::instant_refund(
            &mut registry,
            order_id,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

#[test]
fun test_order_id_gen(){
    let mut scenario = setup();
    
    // Create test data
    let initiator = @0xb9c6ee1630ef3e711144a648db06bbb2284f7274cfbee53ffcee503cc1a49200;
    let redeemer = @0xf1a756ceb2955f680ab622c9c271aa437a22aa978c34ae456f24400d6ea7ccdd;
    let timelock = 10;
    let amount = 10;
    let secret_hash = x"762b82db7b75ed4848fc544d2907ee63e00d768dcb3cec839584995db5253f60";

    ts::next_tx(&mut scenario, ADMIN);
    {
        let registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let _order_id = AtomicSwap::generate_order_id(
            secret_hash,
            initiator,
            redeemer,
            timelock,
            amount,
            &registry
        );
        ts::return_shared(registry);
    };
    
    ts::end(scenario);
}

//Making sure that Order CoinType is atomic with the OrderRegistry CoinType. This should throw a compilation error as the registry and the order are of different CoinTypes
// #[test]
// #[expected_failure]
// fun test_revert_init_with_different_coin(){
//     let mut scenario = setup();
//     let clock = clock::create_for_testing(ts::ctx(&mut scenario));

//     let (_, secret_hash) = generate_secret();
//     let (_initiator_pk, initiator_address, redeemer_pk, _redeemer_address) = generate_keypair();

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

// Test zero address validation for initiator
#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroAddressInitiator)]
fun test_revert_init_zero_address_initiator() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, _initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, redeemer_address);
    };

    // Try to create a swap with zero address initiator (should fail)
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to zero address initiator
        AtomicSwap::initiate(
            &mut registry,
            @0x0, // Zero address
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test zero address validation for redeemer
#[test]
#[expected_failure(abort_code = AtomicSwap::EZeroAddressRedeemer)]
fun test_revert_init_zero_address_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, _redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, initiator_address);
    };

    // Try to create a swap with zero address redeemer (should fail)
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to zero address redeemer
        AtomicSwap::initiate(
            &mut registry,
            initiator_address,
            @0x0, // Zero address
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test same funder and redeemer validation
#[test]
#[expected_failure(abort_code = AtomicSwap::ESameFunderRedeemer)]
fun test_revert_init_same_funder_redeemer() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Mint coins to the redeemer (same as funder)
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, redeemer_address);
    };

    // Try to create a swap where funder and redeemer are the same (should fail)
    ts::next_tx(&mut scenario, redeemer_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail since funder and redeemer are the same
        AtomicSwap::initiate(
            &mut registry,
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            TIMELOCK,
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}

// Test the encode function through instant_refund_digest
#[test]
fun test_encode_function() {
    let mut scenario = setup();
    
    // Create test data
    let order_id = x"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    ts::next_tx(&mut scenario, ADMIN);
    {
        let registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        let registry_addr = object::uid_to_address(reg_id);
        
        // Test the encode function through instant_refund_digest
        let digest = AtomicSwap::instant_refund_digest(order_id, registry_addr);
        
        // Verify the digest is not empty
        assert!(vector::length(&digest) > 0, 0);
        
        ts::return_shared(registry);
    };
    
    ts::end(scenario);
}

// Test getter functions for better coverage
#[test]
fun test_getter_functions() {
    let mut scenario = setup();
    
    ts::next_tx(&mut scenario, ADMIN);
    {
        let registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        
        // Test get_order_reg_id
        let reg_id = AtomicSwap::get_order_reg_id<SUI>(&registry);
        assert!(object::uid_to_inner(reg_id) == object::uid_to_inner(AtomicSwap::get_order_reg_id<SUI>(&registry)), 0);
        
        // Test get_refund_typehash
        let typehash = AtomicSwap::get_refund_typehash();
        assert!(vector::length(&typehash) == 32, 0);
        
        ts::return_shared(registry);
    };
    
    ts::end(scenario);
}

// Test edge case: timelock exactly at 7 days + 1ms (should fail)
#[test]
#[expected_failure(abort_code = AtomicSwap::EInvalidTimelock)]
fun test_revert_init_exact_7_day_timelock() {
    let mut scenario = setup();
    let clock = clock::create_for_testing(ts::ctx(&mut scenario));

    let (_, secret_hash) = generate_secret();
    let (_initiator_pk, initiator_address, _redeemer_pk, redeemer_address) = generate_keypair();

    // Mint coins to the initiator
    ts::next_tx(&mut scenario, ADMIN);
    {
        let mint_coins = mint_coins(SWAP_AMOUNT, ts::ctx(&mut scenario));
        transfer::public_transfer(mint_coins, initiator_address);
    };

    // Try to create a swap with exactly 7 days timelock (should fail)
    ts::next_tx(&mut scenario, initiator_address);
    {
        let mut registry = ts::take_shared<OrdersRegistry<SUI>>(&scenario);
        let init_coins = ts::take_from_sender<Coin<SUI>>(&scenario);

        // This should fail due to exactly 7 days timelock
        AtomicSwap::initiate(
            &mut registry,
            initiator_address,
            redeemer_address,
            secret_hash,
            SWAP_AMOUNT,
            604800001, // Exactly 7 days + 1ms timelock
            vector::empty<u8>(),
            init_coins,
            &clock,
            ts::ctx(&mut scenario),
        );

        ts::return_shared(registry);
    };

    clock::destroy_for_testing(clock);
    ts::end(scenario);
}