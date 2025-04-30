// import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
// import { getFaucetHost, requestSuiFromFaucetV1 } from "@mysten/sui/faucet";
// import { MIST_PER_SUI } from "@mysten/sui/utils";
// import { Transaction } from "@mysten/sui/transactions";
// import { Ed25519Keypair, Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
// import { Secp256k1Keypair } from "@mysten/sui/keypairs/secp256k1";
// import { fromHex, SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";
// import crypto from 'crypto';
// import keccak256 from "keccak256";

// const ALICE =
//   "0x6327b12f0e672c857cf562e9d3ac96e488b921e9e91d5b3f5bf0e8f54707ea11";
// const BOB =
//   "0x054978ec2cf9219920af04e9a756d3518c4dee3c4d4198561f6a7c8e7d84c094";
// const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });
// const package_add =
//   "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493";
// const keypairAlice = Ed25519Keypair.fromSecretKey(
//   "suiprivkey1qqewlt0qrzkp8w9tm35mf7qgnuwtuszrfpw3cf78vrwet9vef5gh2tyz900"
// );//32efade018ac13b8abdc69b4f8089f1cbe4043485d1c27c760dd9595994d1175
// const keypairBob = Ed25519Keypair.fromSecretKey(
//   "suiprivkey1qzwgahx9nz062araz32vgyq4ryhth93s35a5375cm9ymf8x3kg3pqsgyat4"
// );//9c8edcc5989fa5747d1454c41015192ebb96308d3b48fa98d949b49cd1b22210

// const tx = new Transaction();
// tx.setGasBudget(100000000);

// //-------------------------------CREATE_ORDER_REGISTRY------------------------------------//
// // let order_reg_id;
// // let order_reg_id = tx.moveCall({
// //   	target: '0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::create_orders_registry',
// //   	// object IDs must be wrapped in moveCall arguments
// //       typeArguments: ['0x2::sui::SUI'],
// //   	arguments: [],
// // });
// // console.log(order_reg_id);
// //----------------------------------------------------------------------------------------//
// let init_add = fromHex(BOB);

// // 0) redeemer_address
// const bytesPkAlice = keypairAlice.getPublicKey().toRawBytes();
// const publicKeyAlice = new Ed25519PublicKey(bytesPkAlice).toRawBytes();
// const bytesPkBob = keypairBob.getPublicKey().toRawBytes();
// const publicKeyBob = new Ed25519PublicKey(bytesPkBob).toRawBytes();
// console.log("Public Key Bob: ", Buffer.from(publicKeyBob).toString('hex'));
// console.log("Public Key Alice: ", Buffer.from(publicKeyAlice).toString('hex'));

// // 1) order_registry
// const order_reg_id = "0x09490c1aab084cbbe93772819bb9c415a2ddaf4398ea91a858934e176b4af984";
// let order_reg = tx.object(order_reg_id);
// console.log("THIS IS ORDER REGISTRY : ->>>>>>> ", order_reg);
// // 2) secret
// let secret = "test3";
// const secretHash = crypto.createHash('sha256').update(secret).digest();
// console.log(secretHash);
// console.log("Secret hash: ", secretHash.toString('hex'));

// function createOrderId(secretHash, initiatorAddress) {
//   const initiatorHex = initiatorAddress.startsWith('0x') ? initiatorAddress.slice(2) : initiatorAddress;
//   const initiatorBytes = Buffer.from(initiatorHex, 'hex');

//   const suiChainId = Buffer.alloc(32, 0);

//   // Concatenate in the exact same order as in the Move contract
//   const data = Buffer.concat([
//     Buffer.from(secretHash),
//     initiatorBytes,
//     suiChainId
//   ]);

//   return crypto.createHash('sha256').update(data).digest();
// }

// // 3) order_id
// const orderIdBytes = createOrderId(secretHash, ALICE);
// console.log("Order ID:", orderIdBytes.toString('hex'));
// // const data = Buffer.concat([secretHash, init_add, sui_chain_id]);
// // console.log("Concatenated byte array:", data);
// // const orderIdBytes = crypto.createHash('sha256').update(data).digest();
// // console.log("SHA-256 hash of concatenated byte arrays:", fromHex(orderIdBytes));
// // console.log(orderIdBytes);

// // 4) timelock
// let timelock = 3 * 60 * 1000;

// // 5) amount
// let amount = 10000;

// // 6) coins
// const [coin] = tx.splitCoins(tx.gas, [amount]);

// //-------------------------------------------INITIALIZE_SWAP--------------------------------------------//
// // tx.moveCall({
// //   target:
// //     "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::initiate",
// //   typeArguments: ["0x2::sui::SUI"],
// //   arguments: [
// //     tx.object(order_reg_id),
// //     tx.pure.address(BOB),
// //     tx.pure.vector("u8", publicKeyBob),
// //     tx.pure.vector("u8", secretHash),
// //     tx.pure.u64(amount),
// //     tx.pure.u64(timelock),
// //     coin,
// //     tx.object(SUI_CLOCK_OBJECT_ID),
// //   ],
// // });
// //-------------------------------------------------------------------------------------------------------//
// function initiateDigest(redeemer, timelock, amount, secretHash) {
//   // Create the type hash - must match EXACTLY what's in the contract
//   const INITIATE_TYPEHASH = Buffer.from("Initiate(address redeemer,uint256 timelock,uint256 amount,bytes32 secretHash)");

//   // Apply keccak256 to get the typehash bytes as done in the contract
//   // const typeHashBytes = keccak256(INITIATE_TYPEHASH);
//   const redeemer_add = redeemer.startsWith('0x') ? redeemer.slice(2) : redeemer;
//   const redeemer_bytes = Buffer.from(redeemer_add, 'hex');
//   // Encode according to the contract's encode function
//   let data = Buffer.concat([INITIATE_TYPEHASH, redeemer_bytes, Buffer.from(timelock.toString()), Buffer.from(amount.toString()), Buffer.from(secretHash)]);
//   return keccak256(data);
// }

// const initDigest = initiateDigest(BOB, timelock, amount, secretHash);
// console.log("Init digest to sign:", initDigest.toString('hex'));
// //0xad80c069df4afa2ffca1b42acbb53942b8428530a1fc712940fa1a9a1c424794
// const initSignature = await keypairAlice.sign(initDigest);
// console.log("Signature:", Buffer.from(initSignature).toString('hex'));
// //-------------------------------------------INITIALIZE_WITH_SIG--------------------------------------------//
// // tx.moveCall({
// //   target:
// //     "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::initiate_with_sig",
// //     arguments: [
// //       tx.object(order_reg_id),
// //       tx.pure.address(ALICE),
// //       tx.pure.vector("u8", publicKeyAlice),
// //       tx.pure.address(BOB),
// //       tx.pure.vector("u8", publicKeyBob),
// //       tx.pure.vector("u8", initSignature),
// //       tx.pure.vector("u8", secretHash),
// //       tx.pure.u64(amount),
// //       tx.pure.u64(timelock),
// //       coin,
// //       tx.object(SUI_CLOCK_OBJECT_ID),
// //     ],
// //     typeArguments: ["0x2::sui::SUI"],
// // });
// //-------------------------------------------------------------------------------------------------------//
// //-------------------------------------------REFUND_SWAP-------------------------------------------------//
// // tx.moveCall({
// //     target: "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::refund_swap",
// //     typeArguments: ["0x2::sui::SUI"],
// //     arguments: [
// //         order_reg,
// //         tx.pure.vector("u8", orderIdBytes),
// //         tx.object(SUI_CLOCK_OBJECT_ID)
// //       ]
// //     })
// //-------------------------------------------------------------------------------------------------------//
// //-------------------------------------------REDEEM_SWAP-------------------------------------------------//
// // tx.moveCall({
// //     target: "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::redeem_swap",
// //     typeArguments: ["0x2::sui::SUI"],
// //     arguments: [
// //         order_reg,
// //         tx.pure.vector("u8", orderIdBytes),
// //         tx.pure.vector("u8", Buffer.from(secret)),
// //         tx.object(SUI_CLOCK_OBJECT_ID)
// //       ]
// //     })
// //-------------------------------------------------------------------------------------------------------//
// function instantRefundDigest(orderId) {
//   // Create the type hash - must match EXACTLY what's in the contract
//   const REFUND_TYPEHASH = Buffer.from("Refund(bytes32 orderId)");

//   // Apply keccak256 to get the typehash bytes as done in the contract
//   // const typeHashBytes = keccak256(REFUND_TYPEHASH);

//   // Encode according to the contract's encode function
//   let data = Buffer.concat([REFUND_TYPEHASH, orderId]);
//   return keccak256(data);
// }

// const refundDigest = instantRefundDigest(orderIdBytes);
// console.log("Refund digest to sign:", refundDigest.toString('hex'));

// const refundSignature = await keypairBob.sign(refundDigest);
// console.log("Signature:", Buffer.from(refundSignature).toString('hex'));
// //----------------------------------------INSTANT_REFUND-------------------------------------------------//
// tx.moveCall({
//   target: `${package_add}::AtomicSwap::instant_refund`,
//   typeArguments: ["0x2::sui::SUI"],
//   arguments: [
//     tx.object(order_reg_id),
//     tx.pure.vector("u8", orderIdBytes),
//     tx.pure.vector("u8", Buffer.from(refundSignature)),
//     tx.object(SUI_CLOCK_OBJECT_ID)
//   ]
// });
// //-------------------------------------------------------------------------------------------------------//

// const result = await suiClient.signAndExecuteTransaction({
//   transaction: tx,
//   signer: keypairAlice,
//   options: {
//     showEffects: true,
//   },
// });

// const transaction = await suiClient.waitForTransaction({
//   digest: result.digest,
//   options: {
//     showEffects: true,
//   },
// });

// console.log(result);
// console.log("-------------------");
// console.log(transaction);

// //--------------------------------------------------------------------------------------------------------------------------------

import { getFullnodeUrl, SuiClient } from "@mysten/sui/client";
import { Transaction } from "@mysten/sui/transactions";
import { Ed25519Keypair, Ed25519PublicKey } from "@mysten/sui/keypairs/ed25519";
import { fromHex, SUI_CLOCK_OBJECT_ID } from "@mysten/sui/utils";
import crypto from "crypto";
import keccak256 from "keccak256";
import { toB64 } from "@mysten/sui/utils";

async function executeWithSponsor() {
  const ALICE =
    "0x6327b12f0e672c857cf562e9d3ac96e488b921e9e91d5b3f5bf0e8f54707ea11";
  const BOB =
    "0x054978ec2cf9219920af04e9a756d3518c4dee3c4d4198561f6a7c8e7d84c094";
  const suiClient = new SuiClient({ url: getFullnodeUrl("testnet") });
  const package_add =
    "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493";
  const keypairAlice = Ed25519Keypair.fromSecretKey(
    "suiprivkey1qqewlt0qrzkp8w9tm35mf7qgnuwtuszrfpw3cf78vrwet9vef5gh2tyz900"
  ); //32efade018ac13b8abdc69b4f8089f1cbe4043485d1c27c760dd9595994d1175
  const keypairBob = Ed25519Keypair.fromSecretKey(
    "suiprivkey1qzwgahx9nz062araz32vgyq4ryhth93s35a5375cm9ymf8x3kg3pqsgyat4"
  ); //9c8edcc5989fa5747d1454c41015192ebb96308d3b48fa98d949b49cd1b22210
  const bytesPkAlice = keypairAlice.getPublicKey().toRawBytes();
  const publicKeyAlice = new Ed25519PublicKey(bytesPkAlice).toRawBytes();
  const bytesPkBob = keypairBob.getPublicKey().toRawBytes();
  const publicKeyBob = new Ed25519PublicKey(bytesPkBob).toRawBytes();

  // Create a new transaction
  const tx = new Transaction();
  tx.setGasBudget(100000000);

  // Add your transaction logic below (using the instant_refund example)
  const order_reg_id =
    "0x09490c1aab084cbbe93772819bb9c415a2ddaf4398ea91a858934e176b4af984";
  let order_reg = tx.object(order_reg_id);

  let secret = "test5";
  const secretHash = crypto.createHash("sha256").update(secret).digest();

  function createOrderId(secretHash, initiatorAddress) {
    const initiatorHex = initiatorAddress.startsWith("0x")
      ? initiatorAddress.slice(2)
      : initiatorAddress;
    const initiatorBytes = Buffer.from(initiatorHex, "hex");

    const suiChainId = Buffer.alloc(32, 0);

    // Concatenate in the exact same order as in the Move contract
    const data = Buffer.concat([
      Buffer.from(secretHash),
      initiatorBytes,
      suiChainId,
    ]);

    return crypto.createHash("sha256").update(data).digest();
  }

  const orderIdBytes = createOrderId(secretHash, ALICE);
  // 4) timelock
  let timelock = 3 * 60 * 1000;

  //  5) amount
  let amount = 10000;

  // 6) coins
  const [coin] = tx.splitCoins(tx.gas, [amount]);

  function instantRefundDigest(orderId) {
    const REFUND_TYPEHASH = Buffer.from("Refund(bytes32 orderId)");
    let data = Buffer.concat([REFUND_TYPEHASH, orderId]);
    return keccak256(data);
  }

  const refundDigest = instantRefundDigest(orderIdBytes);
  const refundSignature = await keypairBob.sign(refundDigest);

  //-------------------------------------------INITIALIZE_SWAP--------------------------------------------//
  tx.moveCall({
    target:
      "0xc67bb79f8b7ab6bb34f796adc026996f73c978db01d567bcf5fb3db774384493::AtomicSwap::initiate",
    typeArguments: ["0x2::sui::SUI"],
    arguments: [
      tx.object(order_reg_id),
      tx.pure.address(BOB),
      tx.pure.vector("u8", publicKeyBob),
      tx.pure.vector("u8", secretHash),
      tx.pure.u64(amount),
      tx.pure.u64(timelock),
      coin,
      tx.object(SUI_CLOCK_OBJECT_ID),
    ],
  });
  //-------------------------------------------------------------------------------------------------------//

  const bobCoins = await suiClient.getCoins({
    owner: BOB,
    coinType: "0x2::sui::SUI",
  });

  if (bobCoins.data.length === 0) {
    throw new Error("Bob has no SUI coins for gas payment");
  }

  // Set a specific coin from Bob to be used for gas payment
  // const gasCoin = bobCoins.data[0].coinObjectId;
  const bobCoin = bobCoins.data[0];
  const coinObjectRef = {
    objectId: bobCoin.coinObjectId,
    version: bobCoin.version,
    digest: bobCoin.digest,
  };
  tx.setGasPayment([coinObjectRef]);

  // This is critical: explicitly set the gas owner to Bob's address
  tx.setSender(ALICE); // Transaction sender is still Alice
  tx.setGasOwner(BOB); // But gas will be paid by Bob

  // Step 1: Build the transaction and get the transaction bytes
  const serializedTx = await tx.build({
    client: suiClient
  });
  // const serializedTx = await txBlock.getSerializedTransaction();
  // Get signatures from both parties
  // 1. Alice signs as the transaction sender
  const aliceSignature = (await keypairAlice.signTransaction(serializedTx)).signature;
  const bobSignature = (await keypairBob.signTransaction(serializedTx)).signature;

  /// Execute with both signatures
  const result = await suiClient.executeTransactionBlock({
    transactionBlock: serializedTx,
    signature: [bobSignature, aliceSignature],
    options: {
      showEffects: true,
      showEvents: true,
    },
  });

  // Wait for transaction confirmation
  const transaction = await suiClient.waitForTransaction({
    digest: result.digest,
  });

  return { result, transaction };
}
// Execute the sponsored transaction
executeWithSponsor()
  .then(({ result, transaction }) => {
    console.log("Transaction successfully executed!");
    console.log("Result:", result);
    console.log("Transaction details:", transaction);
  })
  .catch((error) => {
    console.error("Error executing sponsored transaction:", error); 
  });
// console.log("Transaction result:", result);
// console.log("-------------------");
// console.log("Transaction details:", transaction);
