import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import fs from "fs";
import path from "path";

// Configuration
const NETWORK = (process.env.SUI_NETWORK || "testnet") as
  | "testnet"
  | "mainnet"
  | "devnet";
const PRIVATE_KEY = process.env.SUI_PRIVATE_KEY;
const PACKAGE_ID = process.env.SUI_PACKAGE_ID;

if (!PRIVATE_KEY) {
  console.error("❌ SUI_PRIVATE_KEY environment variable is required");
  console.error('Example: export SUI_PRIVATE_KEY="suiprivkey1..."');
  process.exit(1);
}

if (!PACKAGE_ID) {
  console.error("❌ SUI_PACKAGE_ID environment variable is required");
  console.error('Example: export SUI_PACKAGE_ID="0x..."');
  process.exit(1);
}

async function createRegistry() {
  try {
    console.log(`🏗️  Creating Orders Registry on ${NETWORK}...`);

    // Load your keypair
    const keypair = Ed25519Keypair.fromSecretKey(PRIVATE_KEY!);
    const address = keypair.getPublicKey().toSuiAddress();
    console.log(`📋 Deployer address: ${address}`);
    console.log(`📦 Package ID: ${PACKAGE_ID}`);

    // Create the transaction
    const tx = new Transaction();
    tx.setGasBudget(100000000);

    // Create orders registry
    const orderRegId = tx.moveCall({
      target: `${PACKAGE_ID}::AtomicSwap::create_orders_registry`,
      typeArguments: ["0x2::sui::SUI"],
      arguments: [],
    });

    console.log(`🔧 Order Registry ID: ${orderRegId}`);

    // Send the transaction
    const client = new SuiClient({ url: getFullnodeUrl(NETWORK) });

    console.log("📡 Submitting transaction...");
    const result = await client.signAndExecuteTransaction({
      signer: keypair,
      transaction: tx,
      options: {
        showEffects: true,
        showObjectChanges: true,
        showEvents: true,
      },
      requestType: "WaitForLocalExecution",
    });

    if (result.effects?.status.status === "success") {
      console.log("✅ Registry creation successful!");
      console.log(`🔗 Transaction: ${result.digest}`);

      // Extract registry ID from object changes
      const registryCreated = result.objectChanges?.find(
        (change) =>
          change.type === "created" &&
          "objectType" in change &&
          change.objectType?.includes("OrdersRegistry")
      );

      if (registryCreated && "objectId" in registryCreated) {
        console.log(`📋 Registry ID: ${registryCreated.objectId}`);
      }

      // Save registry info
      const registryInfo = {
        network: NETWORK,
        deployer: address,
        packageId: PACKAGE_ID,
        registryId:
          registryCreated && "objectId" in registryCreated
            ? registryCreated.objectId
            : null,
        transaction: result.digest,
        timestamp: new Date().toISOString(),
        effects: result.effects,
        objectChanges: result.objectChanges,
      };

      const registryPath = path.join(
        __dirname,
        "..",
        `registry-${NETWORK}.json`
      );
      fs.writeFileSync(registryPath, JSON.stringify(registryInfo, null, 2));
      console.log(`📄 Registry info saved to: ${registryPath}`);
    } else {
      console.error("❌ Registry creation failed!");
      console.error("Effects:", result.effects);
      process.exit(1);
    }
  } catch (error) {
    console.error("❌ Registry creation error:", error);
    process.exit(1);
  }
}

// Run registry creation
createRegistry();
