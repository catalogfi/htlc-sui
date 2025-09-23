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
const PACKAGE_ID = process.env.SUI_PACKAGE_ID; // Package that contains AtomicSwap and UDA
const COIN_TYPE = process.env.SUI_COIN_TYPE || "0x2::sui::SUI";

// Optional: allow overriding AdminCap/RegistryMapping via env
const UDA_ADMIN_CAP_ID_ENV = process.env.UDA_ADMIN_CAP_ID;
const UDA_REGISTRY_MAPPING_ID_ENV = process.env.UDA_REGISTRY_MAPPING_ID;

if (!PRIVATE_KEY) {
  console.error("❌ SUI_PRIVATE_KEY environment variable is required");
  console.error('Example: export SUI_PRIVATE_KEY="suiprivkey1..."');
  process.exit(1);
}

// PACKAGE_ID is optional; if not provided, we'll read from deployment-<net>.json later

async function createRegistry() {
  try {
    console.log("\n==================================================");
    console.log(
      `🏗️  Creating AtomicSwap::OrdersRegistry and mapping via UDA | network=${NETWORK}`
    );
    console.log("==================================================\n");

    // Load your keypair
    const keypair = Ed25519Keypair.fromSecretKey(PRIVATE_KEY!);
    const address = keypair.getPublicKey().toSuiAddress();
    console.log(`📋 signer=${address}`);

    // Resolve packageId from env or deployment file
    let packageId = PACKAGE_ID || "";
    if (!packageId) {
      const depPath = path.join(
        __dirname,
        "..",
        "artifacts",
        `deployment-${NETWORK}.json`
      );
      if (fs.existsSync(depPath)) {
        try {
          const dep = JSON.parse(fs.readFileSync(depPath, "utf8"));
          packageId = dep.packageId || "";
        } catch {}
      }
    }

    if (!packageId) {
      console.error(
        "❌ Missing packageId. Set SUI_PACKAGE_ID or ensure deployment-<net>.json exists with packageId."
      );
      process.exit(1);
    }
    console.log(`📦 packageId=${packageId}`);

    // Create the transaction
    const tx = new Transaction();
    tx.setGasBudget(100000000);

    // Create orders registry
    const orderRegId = tx.moveCall({
      target: `${packageId}::AtomicSwap::create_orders_registry`,
      typeArguments: [COIN_TYPE],
      arguments: [],
    });

    console.log(`🔧 orderRegId(tmp)=${orderRegId}`);

    // Send the transaction
    const client = new SuiClient({ url: getFullnodeUrl(NETWORK) });

    console.log("📡 Submitting create_orders_registry transaction...");
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
      console.log("✅ create_orders_registry succeeded");
      console.log(`🔗 txDigest=${result.digest}`);

      // Extract registry ID from object changes
      const registryCreated = result.objectChanges?.find(
        (change) =>
          change.type === "created" &&
          "objectType" in change &&
          change.objectType?.includes("OrdersRegistry")
      );

      const createdRegistryId =
        registryCreated && "objectId" in registryCreated
          ? (registryCreated.objectId as string)
          : "";

      if (createdRegistryId) console.log(`📋 registryId=${createdRegistryId}`);

      // Prepare to call UDA::add_reg_id with this registry
      let udaAdminCapId = UDA_ADMIN_CAP_ID_ENV || "";
      let udaRegistryMappingId = UDA_REGISTRY_MAPPING_ID_ENV || "";

      const deploymentPath = path.join(
        __dirname,
        "..",
        "artifacts",
        `deployment-${NETWORK}.json`
      );
      if (fs.existsSync(deploymentPath)) {
        try {
          const dep = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
          udaAdminCapId = udaAdminCapId || dep.udaAdminCapId || dep.adminCapId;
          udaRegistryMappingId =
            udaRegistryMappingId ||
            dep.udaRegistryMappingId ||
            dep.registryMappingId;
        } catch {}
      }

      if (!udaAdminCapId || !udaRegistryMappingId || !createdRegistryId) {
        console.warn(
          "⚠️  Missing UDA identifiers or created registry id; skipping add_reg_id call."
        );
      }

      let addRegTxDigest: string | null = null;
      if (udaAdminCapId && udaRegistryMappingId && createdRegistryId) {
        console.log(
          `🔧 Mapping ${COIN_TYPE} => ${createdRegistryId} via UDA::add_reg_id...`
        );
        const tx2 = new Transaction();
        tx2.setGasBudget(50_000_000);
        tx2.moveCall({
          target: `${packageId}::UDA::add_reg_id`,
          typeArguments: [COIN_TYPE],
          arguments: [
            tx2.object(udaAdminCapId),
            tx2.object(udaRegistryMappingId),
            tx2.pure.address(createdRegistryId as `0x${string}`),
          ],
        });

        console.log("📡 Submitting UDA::add_reg_id transaction...");
        const res2 = await client.signAndExecuteTransaction({
          signer: keypair,
          transaction: tx2,
          options: {
            showEffects: true,
            showObjectChanges: true,
            showEvents: true,
          },
          requestType: "WaitForLocalExecution",
        });

        if (res2.effects?.status.status === "success") {
          addRegTxDigest = res2.digest;
          console.log("✅ add_reg_id succeeded");
          console.log(`🔗 txDigest=${addRegTxDigest}`);
        } else {
          console.error("❌ add_reg_id failed!", res2.effects);
        }
      }

      // Persist per-transaction artifacts
      const artifactsDir = path.join(__dirname, "..", "artifacts");
      if (!fs.existsSync(artifactsDir)) fs.mkdirSync(artifactsDir);
      const createArtifactPath = path.join(
        artifactsDir,
        `tx-${NETWORK}-create-registry-${result.digest}.json`
      );
      fs.writeFileSync(
        createArtifactPath,
        JSON.stringify(
          {
            kind: "create_orders_registry",
            network: NETWORK,
            txDigest: result.digest,
            packageId,
            coinType: COIN_TYPE,
            registryId: createdRegistryId || null,
            timestamp: new Date().toISOString(),
            signer: address,
            effects: result.effects,
            objectChanges: result.objectChanges,
            events: result.events,
          },
          null,
          2
        )
      );
      console.log(`📝 wrote artifact: ${createArtifactPath}`);

      if (addRegTxDigest) {
        const mapArtifactPath = path.join(
          artifactsDir,
          `tx-${NETWORK}-uda-add-reg-id-${addRegTxDigest}.json`
        );
        fs.writeFileSync(
          mapArtifactPath,
          JSON.stringify(
            {
              kind: "uda_add_reg_id",
              network: NETWORK,
              txDigest: addRegTxDigest,
              packageId,
              coinType: COIN_TYPE,
              registryId: createdRegistryId,
              udaAdminCapId,
              udaRegistryMappingId,
              timestamp: new Date().toISOString(),
              signer: address,
            },
            null,
            2
          )
        );
        console.log(`📝 wrote artifact: ${mapArtifactPath}`);
      }

      // Save combined summary
      const registryInfo = {
        network: NETWORK,
        deployer: address,
        packageId: packageId,
        coinType: COIN_TYPE,
        registryId: createdRegistryId || null,
        createRegistryTx: result.digest,
        addRegIdTx: addRegTxDigest,
        timestamp: new Date().toISOString(),
        effects: result.effects,
        objectChanges: result.objectChanges,
      };

      // Reuse artifactsDir for summary output
      const registryPath = path.join(artifactsDir, `registry-${NETWORK}.json`);
      fs.writeFileSync(registryPath, JSON.stringify(registryInfo, null, 2));
      console.log(`📄 wrote summary: ${registryPath}`);
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
