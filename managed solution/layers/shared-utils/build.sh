#!/bin/bash
# Build the shared utilities Lambda Layer.
# Copies shared/*.py into python/shared/ so Lambda can import from "shared.xxx".

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMBDA_SHARED="$SCRIPT_DIR/../../lambda/shared"
LAYER_DIR="$SCRIPT_DIR/python/shared"

echo "==> Building shared utilities layer..."
rm -rf "$SCRIPT_DIR/python"
mkdir -p "$LAYER_DIR"
cp "$LAMBDA_SHARED"/*.py "$LAYER_DIR/"
echo "==> Done. Layer ready at: $SCRIPT_DIR/python/"
