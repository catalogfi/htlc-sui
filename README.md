# SUI Atomic Swap Contract

A trustless atomic swap implementation on the SUI blockchain, written in Move.

## Overview

This contract implements Hash Time Locked Contracts (HTLCs) for atomic swaps on SUI, enabling secure cross-chain cryptocurrency exchanges without intermediaries. The contract ensures that either both parties receive their tokens or both parties get refunded - there's no middle ground.

To understand atomic swaps fundamentals, please refer to the [Garden Finance documentation](https://docs.garden.finance/home/fundamentals/introduction/atomic-swaps).

For the original Solidity implementation that inspired this contract, see: [HTLC EVM](https://docs.garden.finance/developers/contracts/htlc-evm)

## Key Features

- **Trustless Swaps**: No intermediaries required
- **Time-locked Security**: Automatic refunds after expiration
- **Signature Support**: Instant refunds with redeemer signature
- **Generic Coin Support**: Works with any SUI coin type
- **Event Emission**: Full transparency through event logs

## Architecture

### Core Data Structures

#### `Order<CoinType>`

Represents an individual atomic swap with the following properties:

- `id`: Unique identifier for the order
- `is_fulfilled`: Status flag to prevent double-spending
- `initiator`: Address that created the swap
- `redeemer_pubk`: Public key of the intended recipient
- `amount`: Number of coins being swapped
- `initiated_at`: Timestamp of swap creation
- `coins`: The actual coins being held in escrow
- `timelock`: Duration before refund is allowed

#### `OrdersRegistry<CoinType>`

Central registry that stores all active orders for a specific coin type.

### Event System

The contract emits three types of events for complete transparency:

- **`Initiated`**: When a new swap is created
- **`Redeemed`**: When a swap is successfully completed
- **`Refunded`**: When a swap is refunded to the initiator

## Core Functions

### Creating Orders Registry

```rust
public fun create_orders_registry<CoinType>(ctx: &mut TxContext): ID
```

Creates a new shared registry for managing atomic swaps of a specific coin type.

### Initiating Swaps

```rust
public fun initiate<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    redeemer_pubk: vector<u8>,
    secret_hash: vector<u8>,
    amount: u256,
    timelock: u256,
    coins: Coin<CoinType>,
    clock: &Clock,
    ctx: &mut TxContext
)
```

Creates a new atomic swap order. The initiator deposits coins that can be redeemed by providing the secret or refunded after the timelock expires.

**Parameters:**

- `orders_reg`: Registry to store the order
- `redeemer_pubk`: Ed25519 public key of the intended recipient
- `secret_hash`: SHA-256 hash of the secret
- `amount`: Amount of coins to swap (must match coin value)
- `timelock`: Time period (in milliseconds) before refund is allowed
- `coins`: The coins to be held in escrow
- `clock`: SUI clock object for timestamp
- `ctx`: Transaction context

### Initiating on Behalf

```rust
public fun initiate_on_behalf<CoinType>(...)
```

Allows a third party to create an atomic swap on behalf of another address. Useful for automated systems or relayers.

### Redeeming Swaps

```rust
public fun redeem_swap<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    secret: vector<u8>,
    ctx: &mut TxContext
)
```

Completes an atomic swap by providing the correct secret. The coins are transferred to the redeemer's address.

**Validation:**

- Order must exist and not be fulfilled
- Secret must hash to the stored secret_hash
- Order ID must match the computed ID

### Refunding Swaps

```rust
public fun refund_swap<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext
)
```

Returns coins to the initiator after the timelock has expired.

**Requirements:**

- Order must exist and not be fulfilled
- Current time must exceed `initiated_at + timelock`

### Instant Refunds

```rust
public fun instant_refund<CoinType>(
    orders_reg: &mut OrdersRegistry<CoinType>,
    order_id: vector<u8>,
    signature: vector<u8>,
    ctx: &mut TxContext
)
```

Allows immediate refund with the redeemer's signature, bypassing the timelock. This enables cooperative cancellations.

**Signature Verification:**

- Uses Ed25519 signature scheme
- Message format: `keccak256(REFUND_TYPEHASH + order_id + registry_id)`
- Must be signed by the redeemer's private key

## Order ID Generation

Order IDs are deterministically generated using:

```
SHA-256(chain_id + secret_hash + initiator_address + redeemer_address + timelock)
```

This ensures uniqueness and prevents replay attacks across different parameters.

## Security Features

### Parameter Validation

- Initiator and redeemer must be different addresses
- Amount must be greater than zero
- Timelock must be greater than zero
- Initiator cannot be the zero address
- Coin value must exactly match the specified amount

### Double-Spending Prevention

- Orders are marked as fulfilled after redemption or refund
- Duplicate order IDs are rejected
- State checks prevent multiple operations on the same order

### Cryptographic Security

- Uses SHA-256 for secret hashing
- Ed25519 signatures for instant refunds
- Keccak256 for type hashing and encoding

## Error Codes

| Code | Error                    | Description                               |
| ---- | ------------------------ | ----------------------------------------- |
| 1    | `EIncorrectFunds`        | Coin value doesn't match specified amount |
| 2    | `EOrderNotExpired`       | Timelock hasn't expired yet               |
| 3    | `EZeroAddressInitiator`  | Initiator cannot be zero address          |
| 4    | `EOrderFulfilled`        | Order already completed                   |
| 5    | `EOrderNotInitiated`     | Order doesn't exist                       |
| 6    | `EInvalidSignature`      | Signature verification failed             |
| 7    | `EDuplicateOrder`        | Order ID already exists                   |
| 8    | `EIncorrectSecret`       | Provided secret doesn't match hash        |
| 9    | `EZeroTimelock`          | Timelock cannot be zero                   |
| 10   | `EZeroAmount`            | Amount cannot be zero                     |
| 11   | `ESameInitiatorRedeemer` | Initiator and redeemer cannot be the same |
| 12   | `ESameFunderRedeemer`    | Funder and redeemer cannot be the same    |
| 13   | `EInvalidPubkey`         | Public key must be 32 bytes (Ed25519)     |

## Usage Example

```rust
// 1. Create registry
let registry_id = create_orders_registry<SUI>(ctx);

// 2. Initiate swap
initiate<SUI>(
    registry,
    redeemer_public_key,
    sha256_hash_of_secret,
    1000000000, // 1 SUI in MIST
    3600000,    // 1 hour timelock
    coins,
    clock,
    ctx
);

// 3. Redeem with secret
redeem_swap<SUI>(registry, order_id, secret, ctx);

// OR refund after expiry
refund_swap<SUI>(registry, order_id, clock, ctx);
```

## Chain Configuration

The contract includes chain ID configuration for proper order ID generation:

- **Mainnet**: `0x0000000000000000000000000000000000000000000000000000000000000000`
- **Testnet**: `0x0000000000000000000000000000000000000000000000000000000000000001`

⚠️ **Important**: Update the `sui_chain_id` in `create_order_id()` function before deploying to testnet.

## Supported Cryptography

Currently supports:

- **Ed25519** signatures and public keys (32 bytes)
- **SHA-256** for secret hashing
- **Keccak256** for type hashing
- **BLAKE2b-256** for address generation

## Testing

The contract includes test-only functions for comprehensive testing:

- `get_order()`: Retrieve order details
- `generate_order_id()`: Test order ID generation
- `get_refund_typehash()`: Get refund type hash
- `get_order_reg_id()`: Get registry ID

## Deployment Considerations

1. **Registry Management**: Each coin type requires its own registry
2. **Shared Objects**: Registries are shared objects accessible to all users
3. **Gas Optimization**: Functions are optimized for minimal gas usage
4. **Event Indexing**: Events enable easy tracking of swap lifecycle

## Security Audit Checklist

- [ ] Parameter validation completeness
- [ ] Reentrancy protection (Move's ownership model provides this)
- [ ] Integer overflow protection (Move provides this)
- [ ] Proper access controls
- [ ] Event emission accuracy
- [ ] Error handling completeness
- [ ] Cryptographic implementations
- [ ] Order ID uniqueness and determinism
- [ ] Timelock logic correctness

## License

This contract is part of the Garden Finance protocol implementation for SUI blockchain.

## Contributing

Please ensure all contributions maintain the security standards and include appropriate tests for any new functionality.
