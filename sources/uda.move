module atomic_swapv1::UDA {

    use std::string;
    use std::vector;
    use sui::object::{Self, UID};
    use sui::coin::{Self, Coin, value};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::clock::{Self, Clock};
    use sui::type_name;
    use atomic_swapv1::AtomicSwap;

    public struct InitiateObject<phantom CoinType> has key {
        id: UID,
        initiator: address,
        redeemer: address,
        secret_hash: vector<u8>,
        amount: u64,
        timelock: u64,
        destination_data: vector<u8>,
    }

    public entry fun create_object<CoinType>(
        initiator: address,
        redeemer: address,
        secret_hash: vector<u8>,
        amount: u64,
        timelock: u64,
        destination_data: vector<u8>,
        ctx: &mut TxContext
    ) {
        let obj = InitiateObject<CoinType> {
            id: object::new(ctx),
            initiator,
            redeemer,
            secret_hash,
            amount,
            timelock,
            destination_data
        };
        transfer::transfer(obj, tx_context::sender(ctx));
    }

    public entry fun check_and_trigger<CoinType>(
        obj: &InitiateObject<CoinType>,
        orders_reg: &mut AtomicSwap::OrdersRegistry<CoinType>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // If funded with the correct type and amount, trigger
        if (total == obj.amount) {
            AtomicSwap::initiate<CoinType>(
                orders_reg,
                obj.initiator,
                obj.redeemer,
                obj.secret_hash,
                obj.amount,
                obj.timelock,
                obj.destination_data,
                coin::
                clock,
                ctx
            );
        };
    }
}
