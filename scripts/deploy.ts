import { SuiClient, getFullnodeUrl } from "@mysten/sui/client";
import { Ed25519Keypair } from "@mysten/sui/keypairs/ed25519";
import { Transaction } from "@mysten/sui/transactions";
import { fromB64 } from "@mysten/sui/utils";
import fs from "fs";
import path from "path";

// Configuration
const NETWORK = (process.env.SUI_NETWORK || "testnet") as
  | "testnet"
  | "mainnet"
  | "devnet";
const PRIVATE_KEY = process.env.SUI_PRIVATE_KEY;

if (!PRIVATE_KEY) {
  console.error("❌ SUI_PRIVATE_KEY environment variable is required");
  console.error('Example: export SUI_PRIVATE_KEY="your_private_key_here"');
  process.exit(1);
}

async function deploy() {
  try {
    console.log("\n==================================================");
    console.log(`🚀 Deploying HTLC + UDA package | network=${NETWORK}`);
    console.log("==================================================\n");

    // Load your keypair
    const keypair = Ed25519Keypair.fromSecretKey(PRIVATE_KEY!);
    const address = keypair.getPublicKey().toSuiAddress();
    console.log(`📋 Deployer address: ${address}`);

    // Load the compiled bytecode
    const buildOutputPath = path.join(__dirname, "..", "build_output.json");
    if (!fs.existsSync(buildOutputPath)) {
      console.error(
        "❌ build_output.json not found. Please run the build script first:"
      );
      console.error("   npm run build");
      process.exit(1);
    }

    const buildOutput = JSON.parse(fs.readFileSync(buildOutputPath, "utf8"));
    const modules = buildOutput.modules.map(fromB64);
    const dependencies = buildOutput.dependencies; // These are already strings (object IDs)

    console.log(
      `📦 modules=${modules.length}  🔗 dependencies=${dependencies.length}`
    );

    // Create the publish transaction
    const tx = new Transaction();
    const cap = tx.publish({ modules, dependencies });

    // Transfer the upgrade cap to the deployer
    tx.transferObjects([cap], keypair.getPublicKey().toSuiAddress());

    // Send the transaction
    const client = new SuiClient({ url: getFullnodeUrl(NETWORK) });

    console.log("📡 Submitting publish transaction...");
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
      console.log("✅ Publish succeeded");
      console.log(`🔗 txDigest=${result.digest}`);

      // Extract package ID
      const packageId = result.objectChanges?.find(
        (change) => change.type === "published"
      )?.packageId;

      if (packageId) console.log(`📦 packageId=${packageId}`);

      // Extract UDA AdminCap and RegistryMapping created by UDA::init (if any)
      const adminCap = result.objectChanges?.find(
        (c) =>
          c.type === "created" &&
          "objectType" in c &&
          typeof c.objectType === "string" &&
          c.objectType.includes("::UDA::AdminCap")
      ) as any | undefined;

      const registryMapping = result.objectChanges?.find(
        (c) =>
          c.type === "created" &&
          "objectType" in c &&
          typeof c.objectType === "string" &&
          c.objectType.includes("::UDA::RegistryMapping")
      ) as any | undefined;

      const adminCapId = adminCap?.objectId as string | undefined;
      const registryMappingId = registryMapping?.objectId as string | undefined;

      if (adminCapId) console.log(`🪪 udaAdminCapId=${adminCapId}`);
      if (registryMappingId)
        console.log(`🗺️  udaRegistryMappingId=${registryMappingId}`);

      // Persist detailed per-transaction artifact
      const artifactsDir = path.join(__dirname, "..", "artifacts");
      if (!fs.existsSync(artifactsDir)) fs.mkdirSync(artifactsDir);
      const publishArtifactPath = path.join(
        artifactsDir,
        `tx-${NETWORK}-publish-${result.digest}.json`
      );
      const publishArtifact = {
        kind: "publish",
        network: NETWORK,
        txDigest: result.digest,
        packageId,
        udaAdminCapId: adminCapId || null,
        udaRegistryMappingId: registryMappingId || null,
        timestamp: new Date().toISOString(),
        deployer: address,
        effects: result.effects,
        objectChanges: result.objectChanges,
        events: result.events,
      };
      fs.writeFileSync(
        publishArtifactPath,
        JSON.stringify(publishArtifact, null, 2)
      );
      console.log(`📝 wrote artifact: ${publishArtifactPath}`);

      // Save deployment info
      const deploymentInfo = {
        network: NETWORK,
        deployer: address,
        packageId,
        udaAdminCapId: adminCapId || null,
        udaRegistryMappingId: registryMappingId || null,
        transaction: result.digest,
        timestamp: new Date().toISOString(),
        effects: result.effects,
        objectChanges: result.objectChanges,
      };

      // Reuse artifactsDir for summary output
      const deploymentPath = path.join(
        artifactsDir,
        `deployment-${NETWORK}.json`
      );
      fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
      console.log(`📄 wrote summary: ${deploymentPath}`);
    } else {
      console.error("❌ Deployment failed!");
      console.error("Effects:", result.effects);
      process.exit(1);
    }
  } catch (error) {
    console.error("❌ Deployment error:", error);
    process.exit(1);
  }
}

// Run deployment
deploy();
