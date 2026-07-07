#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Truffle Managed Solution — Full Deployment Script
#
# Deploys the backend infrastructure (API Gateway, Lambda, Step Functions,
# DynamoDB, S3) and builds the custom boto3 Lambda Layer.
#
# Prerequisites:
#   - Node.js >= 18
#   - Python >= 3.11
#   - AWS CDK CLI (npm install -g aws-cdk)
#   - AWS credentials configured (profile or env vars) with admin access
#     to the target deployment account
#   - pip
#
# Usage:
#   ./deploy.sh                          # deploy with defaults
#   ./deploy.sh --profile my-profile     # use a specific AWS profile
#   ./deploy.sh --context orgId=o-abc123 # override the org ID
#
# Environment variables (optional):
#   AWS_PROFILE       — AWS profile to use for deployment
#   TRUFFLE_ORG_ID    — Your AWS Organization ID (default: o-xxxxxxxxxx)
#   TRUFFLE_EXTERNAL_ID — External ID for cross-account trust (default: truffle-default-external-id)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse optional --profile flag
EXTRA_CDK_ARGS=""
for arg in "$@"; do
  EXTRA_CDK_ARGS="$EXTRA_CDK_ARGS $arg"
done

ORG_ID="${TRUFFLE_ORG_ID:-o-xxxxxxxxxx}"
EXTERNAL_ID="${TRUFFLE_EXTERNAL_ID:-truffle-default-external-id}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         Truffle Managed Solution — Deployment               ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Org ID:       $ORG_ID"
echo "║  External ID:  ${EXTERNAL_ID:0:8}..."
echo "║  CDK args:     ${EXTRA_CDK_ARGS:-<none>}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Install CDK dependencies ────────────────────────────────────────
echo "==> [1/5] Installing CDK dependencies..."
npm install

# ─── Step 2: Build the custom boto3 Lambda Layer ─────────────────────────────
echo ""
echo "==> [2/5] Building custom boto3 Lambda Layer..."
cd layers/custom-boto3
bash build.sh
cd "$SCRIPT_DIR"

# ─── Step 3: Compile TypeScript ──────────────────────────────────────────────
echo ""
echo "==> [3/5] Compiling TypeScript..."
npx tsc

# ─── Step 4: CDK Bootstrap (if needed) ───────────────────────────────────────
echo ""
echo "==> [4/5] Bootstrapping CDK (if not already done)..."
npx cdk bootstrap $EXTRA_CDK_ARGS || true

# ─── Step 5: Deploy all stacks ───────────────────────────────────────────────
echo ""
echo "==> [5/5] Deploying all stacks..."
npx cdk deploy --all --require-approval never \
  --context orgId="$ORG_ID" \
  --context externalId="$EXTERNAL_ID" \
  $EXTRA_CDK_ARGS

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Deployment complete!                                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║                                                             ║"
echo "║  Next steps:                                                ║"
echo "║  1. Note the ApiEndpoint output above                       ║"
echo "║  2. Deploy the StackSet to target accounts (see README)     ║"
echo "║  3. Run the UI with:                                        ║"
echo "║                                                             ║"
echo "║     TRUFFLE_MODE=managed \\                                  ║"
echo "║     TRUFFLE_API_ENDPOINT=<ApiEndpoint> \\                    ║"
echo "║     python app.py                                           ║"
echo "║                                                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
