#!/bin/bash
# Build the custom boto3 Lambda Layer from the preview .whl files.
#
# This script installs the custom boto3/botocore wheels (which include the
# AAM "accountaccess" service model) into the layer's python/ directory.
#
# Usage:
#   cd managed-solution/layers/custom-boto3
#   ./build.sh
#
# The resulting python/ directory is what CDK packages as the Lambda Layer.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
LAYER_DIR="$SCRIPT_DIR/python"

echo "==> Cleaning previous build..."
rm -rf "$LAYER_DIR"
mkdir -p "$LAYER_DIR"

echo "==> Installing custom boto3/botocore wheels..."
pip install \
  --target "$LAYER_DIR" \
  --no-deps \
  "$REPO_ROOT/boto3-1.42.97-py3-none-any.whl" \
  "$REPO_ROOT/botocore-1.42.97-py3-none-any.whl"

# Install the required dependencies that botocore/boto3 need but won't be
# in the layer since we used --no-deps. These ARE available in the Lambda
# runtime already, but we include them for completeness / version pinning.
pip install \
  --target "$LAYER_DIR" \
  --no-deps \
  jmespath s3transfer urllib3

echo "==> Layer contents:"
du -sh "$LAYER_DIR"
ls "$LAYER_DIR"

echo "==> Done. Layer ready at: $LAYER_DIR"
