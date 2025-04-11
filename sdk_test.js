import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { getFaucetHost, requestSuiFromFaucetV1 } from "@mysten/sui/faucet";
import { MIST_PER_SUI } from "@mysten/sui/utils";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair, Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import { Secp256k1Keypair } from "@mysten/sui/keypairs/secp256k1";
import { fromHex, SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";
import crypto from 'crypto';
import keccak256 from "keccak256";

const ALICE =
  "0x6327b12f0e672c857cf562e9d3ac96e488b921e9e91d5b3f5bf0e8f54707ea11";
const BOB =
  "0x054978ec2cf9219920af04e9a756d3518c4dee3c4d4198561f6a7c8e7d84c094";
const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });
const package_add =
  "0x5f2a423fd5ccb9245b26c95627368afa9f7576c19d34520d7def5267d5fe72b5";
const keypairAlice = Ed25519Keypair.fromSecretKey(
  "suiprivkey1qqewlt0qrzkp8w9tm35mf7qgnuwtuszrfpw3cf78vrwet9vef5gh2tyz900"
);
const keypairBob = Ed25519Keypair.fromSecretKey(
  "suiprivkey1qzwgahx9nz062araz32vgyq4ryhth93s35a5375cm9ymf8x3kg3pqsgyat4"
);//9c8edcc5989fa5747d1454c41015192ebb96308d3b48fa98d949b49cd1b22210

const tx = new Transaction();
tx.setGasBudget(100000000);

//-------------------------------CREATE_ORDER_REGISTRY------------------------------------//
// let order_reg_id;
// order_reg_id = tx.moveCall({
//   	target: '0x5f2a423fd5ccb9245b26c95627368afa9f7576c19d34520d7def5267d5fe72b5::AtomicSwap::create_orders_registry',
//   	// object IDs must be wrapped in moveCall arguments
//       typeArguments: ['0x2::sui::SUI'],
//   	arguments: [],
// });
// console.log(order_reg_id);
//----------------------------------------------------------------------------------------//
let init_add = fromHex(BOB);

// 0) redeemer_address
const bytesPkAlice = keypairAlice.getPublicKey().toRawBytes();
const publicKeyAlice = new Ed25519PublicKey(bytesPkAlice);
const bytesPkBob = keypairBob.getPublicKey().toRawBytes();
const publicKeyBob = new Ed25519PublicKey(bytesPkBob).toRawBytes();
console.log("Public Key Bob: ", Buffer.from(publicKeyBob).toString('hex'));

// 1) order_registry
const order_reg_id = "0xee6669238ef675289781a753cc994376fc84bc5538bda83edc205d317179f9b4";
let order_reg = tx.object(order_reg_id);

// 2) secret
let secret = "test7";
const secretHash = crypto.createHash('sha256').update(secret).digest();
console.log(secretHash);
console.log("Secret hash: ", secretHash.toString('hex'));

function createOrderId(secretHash, initiatorAddress) {
  const initiatorHex = initiatorAddress.startsWith('0x') ? initiatorAddress.slice(2) : initiatorAddress;
  const initiatorBytes = Buffer.from(initiatorHex, 'hex');
  
  const suiChainId = Buffer.alloc(32, 0);
  
  // Concatenate in the exact same order as in the Move contract
  const data = Buffer.concat([
    Buffer.from(secretHash), 
    initiatorBytes, 
    suiChainId
  ]);
  
  return crypto.createHash('sha256').update(data).digest();
}

// 3) order_id
const orderIdBytes = createOrderId(secretHash, ALICE);
console.log("Order ID:", orderIdBytes.toString('hex'));
// const data = Buffer.concat([secretHash, init_add, sui_chain_id]);
// console.log("Concatenated byte array:", data);
// const orderIdBytes = crypto.createHash('sha256').update(data).digest();
// console.log("SHA-256 hash of concatenated byte arrays:", fromHex(orderIdBytes));
// console.log(orderIdBytes);

// 4) timelock
let timelock = 3 * 60 * 1000;

// 5) amount
let amount = 10000;

// 6) coins
// const [coin] = tx.splitCoins(tx.gas, [amount]);

//-------------------------------------------INITIALIZE_SWAP--------------------------------------------//
// tx.moveCall({
//   target:
//     "0x5f2a423fd5ccb9245b26c95627368afa9f7576c19d34520d7def5267d5fe72b5::AtomicSwap::initialize_Swap",
//   typeArguments: ["0x2::sui::SUI"],
//   arguments: [
//     tx.object(order_reg_id),
//     tx.pure.address(BOB), 
//     tx.pure.vector("u8", publicKeyBob),
//     tx.pure.vector("u8", secretHash),
//     tx.pure.u64(amount),
//     tx.pure.u64(timelock),
//     coin,
//     tx.object(SUI_CLOCK_OBJECT_ID),
//   ],
// });
//-------------------------------------------------------------------------------------------------------//
//-------------------------------------------REFUND_SWAP-------------------------------------------------//
// tx.moveCall({
//     target: "0x5f2a423fd5ccb9245b26c95627368afa9f7576c19d34520d7def5267d5fe72b5::AtomicSwap::refund_Swap",
//     typeArguments: ["0x2::sui::SUI"],
//     arguments: [
//         order_reg,
//         tx.pure.vector("u8", orderIdBytes),
//         tx.object(SUI_CLOCK_OBJECT_ID)
//       ]
//     })
//-------------------------------------------------------------------------------------------------------//
//-------------------------------------------REDEEM_SWAP-------------------------------------------------//
// tx.moveCall({
//     target: "0x5f2a423fd5ccb9245b26c95627368afa9f7576c19d34520d7def5267d5fe72b5::AtomicSwap::redeem_Swap",
//     typeArguments: ["0x2::sui::SUI"],
//     arguments: [
//         order_reg,
//         tx.pure.vector("u8", orderIdBytes),
//         tx.pure.vector("u8", Buffer.from(secret)),
//         tx.object(SUI_CLOCK_OBJECT_ID)
//       ]
//     })
//-------------------------------------------------------------------------------------------------------//
function instantRefundDigest(orderId) {
  // Create the type hash - must match EXACTLY what's in the contract
  const REFUND_TYPEHASH = Buffer.from("Refund(bytes32 orderId)");
  
  // Apply keccak256 to get the typehash bytes as done in the contract
  const typeHashBytes = keccak256(REFUND_TYPEHASH);
  
  // Encode according to the contract's encode function
  let data = Buffer.concat([typeHashBytes, orderId]);
  return keccak256(data);
}

const refundDigest = instantRefundDigest(orderIdBytes);
console.log("Refund digest to sign:", refundDigest.toString('hex'));

const signature = await keypairBob.sign(refundDigest);
console.log("Signature:", Buffer.from(signature).toString('hex'));
//----------------------------------------INSTANT_REFUND-------------------------------------------------//
tx.moveCall({
  target: `${package_add}::AtomicSwap::instant_refund`,
  typeArguments: ["0x2::sui::SUI"],
  arguments: [
    tx.pure.vector("u8", orderIdBytes),
    tx.object(order_reg_id),
    tx.pure.vector("u8", Buffer.from(signature)), 
    tx.object(SUI_CLOCK_OBJECT_ID)
  ]
});
//-------------------------------------------------------------------------------------------------------//


const result = await suiClient.signAndExecuteTransaction({
  transaction: tx,
  signer: keypairAlice,
  options: {
    showEffects: true,
  },
});

const transaction = await suiClient.waitForTransaction({
  digest: result.digest,
  options: {
    showEffects: true,
  },
});

console.log(result);
console.log("-------------------");
console.log(transaction);
