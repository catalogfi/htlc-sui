#!/bin/bash

# Helper script to extract private key from Sui keystore
# This script helps you get your private key in base64 format for deployment

echo "🔑 Sui Private Key Extractor"
echo "=============================="

# Check if keystore exists
KEYSTORE_PATH="$HOME/.sui/sui_config/sui.keystore"
if [ ! -f "$KEYSTORE_PATH" ]; then
    echo "❌ Sui keystore not found at: $KEYSTORE_PATH"
    echo "Please make sure you have Sui CLI installed and configured."
    exit 1
fi

echo "📁 Found keystore at: $KEYSTORE_PATH"
echo ""

# List available keys
echo "🔍 Available keys:"
sui keytool list
echo ""

# Ask for key ID
read -p "Enter the key ID you want to export: " KEY_ID

if [ -z "$KEY_ID" ]; then
    echo "❌ No key ID provided"
    exit 1
fi

echo ""
echo "🔐 Exporting private key for key ID: $KEY_ID"

# Export the private key
EXPORT_OUTPUT=$(sui keytool export --key-identity "$KEY_ID" 2>/dev/null)

if [ $? -eq 0 ]; then
    # Extract the Bech32 private key from the output
    PRIVATE_KEY=$(echo "$EXPORT_OUTPUT" | grep "exportedPrivateKey" | sed 's/.*exportedPrivateKey.*│  \(suiprivkey[^│]*\).*│/\1/' | tr -d ' ')
    
    echo ""
    echo "✅ Private key exported successfully!"
    echo ""
    echo "🔑 Your private key (Bech32 format):"
    echo "export SUI_PRIVATE_KEY=\"$PRIVATE_KEY\""
    echo ""
    echo "📋 Copy the above line and run it in your terminal to set the environment variable."
    echo ""
    echo "⚠️  Security reminder:"
    echo "   - Never share your private key"
    echo "   - Don't commit it to version control"
    echo "   - Store it securely"
else
    echo "❌ Failed to export private key"
    echo "Make sure the key ID is correct and try again."
    exit 1
fi
