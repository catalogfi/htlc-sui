#!/bin/bash

# Build script for HTLC Atomic Swap contract
# This script builds the Move package and outputs bytecode in base64 format

echo "Building HTLC Atomic Swap contract..."

# Build the package and dump bytecode as base64
sui move build --dump-bytecode-as-base64 > build_output.json

if [ $? -eq 0 ]; then
    echo "✅ Build successful! Bytecode saved to build_output.json"
    echo "📁 Build artifacts:"
    ls -la build_output.json
else
    echo "❌ Build failed!"
    exit 1
fi
