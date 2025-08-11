# HTLC Atomic Swap - Deployment Guide

This guide explains how to deploy the HTLC Atomic Swap contract to Sui using the automated deployment scripts.

## Prerequisites

1. **Node.js** (v18 or higher)
2. **Sui CLI** installed and configured
3. **Private Key** for deployment (in base64 format)

## Setup

1. **Install dependencies:**

   ```bash
   npm install
   ```

2. **Set your private key as environment variable:**

   ```bash
   export SUI_PRIVATE_KEY="your_base64_private_key_here"
   ```

   To get your private key in base64 format:

   ```bash
   # If you have a hex private key
   echo "your_hex_private_key" | xxd -r -p | base64

   # Or if you have a Sui keystore file
   sui keytool export --keystore-path ~/.sui/sui_config/sui.keystore --key-id your_key_id
   ```

## Deployment Process

### 1. Build the Contract

Build the Move package and generate bytecode:

```bash
npm run build
```

This creates a `build_output.json` file with the compiled bytecode in base64 format.

### 2. Deploy to Network

Choose your target network:

**Testnet:**

```bash
npm run deploy:testnet
```

**Mainnet:**

```bash
npm run deploy:mainnet
```

**Devnet:**

```bash
npm run deploy:devnet
```

### 3. Create Orders Registry

After deployment, you need to create the Orders Registry (required for contract functionality):

```bash
# Set the package ID from the deployment output
export SUI_PACKAGE_ID="0x..."

# Create registry
npm run create-registry:testnet
npm run create-registry:mainnet
npm run create-registry:devnet
```

### 4. Verify Deployment

After successful deployment, you'll see:

- ✅ Package ID
- ✅ Upgrade Cap ID
- ✅ Transaction hash
- 📄 Deployment info saved to `deployment-{network}.json`

## Environment Variables

| Variable          | Description                             | Required | Default |
| ----------------- | --------------------------------------- | -------- | ------- |
| `SUI_PRIVATE_KEY` | Your private key in base64 format       | Yes      | -       |
| `SUI_NETWORK`     | Target network (testnet/mainnet/devnet) | No       | testnet |
| `SUI_PACKAGE_ID`  | Package ID for registry creation        | Yes\*    | -       |

\*Required only for registry creation step

## Scripts

| Script                            | Description                              |
| --------------------------------- | ---------------------------------------- |
| `npm run build`                   | Build the contract and generate bytecode |
| `npm run deploy:testnet`          | Deploy to Sui testnet                    |
| `npm run deploy:mainnet`          | Deploy to Sui mainnet                    |
| `npm run deploy:devnet`           | Deploy to Sui devnet                     |
| `npm run create-registry:testnet` | Create registry on testnet               |
| `npm run create-registry:mainnet` | Create registry on mainnet               |
| `npm run create-registry:devnet`  | Create registry on devnet                |
| `npm run test`                    | Run Move tests                           |
| `npm run test:coverage`           | Run tests with coverage                  |
| `npm run clean`                   | Clean build artifacts                    |
| `npm run get-key`                 | Extract private key from Sui keystore    |

## Deployment Output

The deployment script creates a `deployment-{network}.json` file containing:

```json
{
  "network": "testnet",
  "deployer": "0x...",
  "packageId": "0x...",
  "upgradeCap": "0x...",
  "transaction": "0x...",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "effects": { ... },
  "objectChanges": [ ... ]
}
```

## Manual Deployment (Alternative)

If you prefer to use the Sui CLI directly:

```bash
# Build
sui move build

# Deploy
sui client publish --gas-budget 100000000
```

## Troubleshooting

### Common Issues

1. **"build_output.json not found"**

   - Run `npm run build` first

2. **"SUI_PRIVATE_KEY environment variable is required"**

   - Set your private key: `export SUI_PRIVATE_KEY="your_key"`

3. **"Deployment failed"**
   - Check your private key format (must be base64)
   - Ensure you have sufficient SUI for gas fees
   - Verify network connectivity

### Getting Your Private Key

```bash
# From Sui keystore
sui keytool export --keystore-path ~/.sui/sui_config/sui.keystore --key-id your_key_id

# Convert hex to base64
echo "your_hex_key" | xxd -r -p | base64
```

## Security Notes

- ⚠️ **Never commit your private key to version control**
- 🔒 Store private keys securely
- 🧪 Test on testnet before mainnet deployment
- 📝 Keep deployment records for reference

## Network URLs

- **Testnet**: `https://fullnode.testnet.sui.io:443`
- **Mainnet**: `https://fullnode.mainnet.sui.io:443`
- **Devnet**: `https://fullnode.devnet.sui.io:443`
