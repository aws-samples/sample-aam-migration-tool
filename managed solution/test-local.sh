#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Test Lambda functions locally using SAM CLI.
#
# Prerequisites:
#   - AWS SAM CLI (brew install aws-sam-cli)
#   - Docker (for SAM local invoke)
#   - CDK synth'd template (run `npx cdk synth` first)
#
# Usage:
#   ./test-local.sh                    # Test the StartJob Lambda
#   ./test-local.sh start-job          # Same as above
#   ./test-local.sh get-status         # Test GetStatus Lambda
#   ./test-local.sh scan-unit          # Test ScanUnit Lambda
#
# This uses `sam local invoke` which spins up a Docker container matching the
# Lambda runtime, mounts your code, and runs it with the test event.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-start-job}"

# ─── Synthesize CDK template if not already done ─────────────────────────────
if [[ ! -d cdk.out ]]; then
  echo "==> Synthesizing CDK template..."
  npx cdk synth --quiet
fi

# Find the workflow stack template (contains the Lambda definitions)
TEMPLATE=$(find cdk.out -name "TruffleWorkflowStack.template.json" | head -1)
if [[ -z "$TEMPLATE" ]]; then
  # Try the API stack for start-job/get-status/get-result
  TEMPLATE=$(find cdk.out -name "TruffleApiStack.template.json" | head -1)
fi

if [[ -z "$TEMPLATE" ]]; then
  echo "ERROR: Could not find synthesized template. Run 'npx cdk synth' first."
  exit 1
fi

# ─── Test events ─────────────────────────────────────────────────────────────
EVENTS_DIR="$SCRIPT_DIR/test-events"
mkdir -p "$EVENTS_DIR"

# Create test events if they don't exist
if [[ ! -f "$EVENTS_DIR/start-job.json" ]]; then
  cat > "$EVENTS_DIR/start-job.json" << 'EOF'
{
  "resource": "/api/idc/discover",
  "path": "/api/idc/discover",
  "httpMethod": "POST",
  "headers": { "Content-Type": "application/json" },
  "queryStringParameters": null,
  "body": "{\"account_scope\": \"single\", \"region\": \"us-east-1\"}",
  "requestContext": {
    "identity": {
      "userArn": "arn:aws:iam::123456789012:user/test-user"
    }
  }
}
EOF
fi

if [[ ! -f "$EVENTS_DIR/get-status.json" ]]; then
  cat > "$EVENTS_DIR/get-status.json" << 'EOF'
{
  "resource": "/api/idc/discover/status",
  "path": "/api/idc/discover/status",
  "httpMethod": "GET",
  "headers": {},
  "queryStringParameters": { "job": "test123abc" },
  "requestContext": {
    "identity": {
      "userArn": "arn:aws:iam::123456789012:user/test-user"
    }
  }
}
EOF
fi

if [[ ! -f "$EVENTS_DIR/scan-unit.json" ]]; then
  cat > "$EVENTS_DIR/scan-unit.json" << 'EOF'
{
  "account_id": "123456789012",
  "region": "us-east-1",
  "search_terms": ["test-idp-arn"],
  "services": ["s3"],
  "job_id": "test123",
  "caller_arn": "arn:aws:iam::123456789012:user/test-user"
}
EOF
fi

# ─── Map target to Lambda logical ID ─────────────────────────────────────────
case "$TARGET" in
  start-job)      FUNCTION_NAME="TruffleStartJob" ;;
  get-status)     FUNCTION_NAME="TruffleGetStatus" ;;
  get-result)     FUNCTION_NAME="TruffleGetResult" ;;
  scan-unit)      FUNCTION_NAME="TruffleScanUnit" ;;
  scan-global)    FUNCTION_NAME="TruffleScanGlobal" ;;
  discover-roles) FUNCTION_NAME="TruffleDiscoverRoles" ;;
  migrate-role)   FUNCTION_NAME="TruffleMigrateRole" ;;
  aggregate)      FUNCTION_NAME="TruffleAggregate" ;;
  *)
    echo "ERROR: Unknown target '$TARGET'. Valid options:"
    echo "  start-job, get-status, get-result, scan-unit, scan-global,"
    echo "  discover-roles, migrate-role, aggregate"
    exit 1
    ;;
esac

EVENT_FILE="$EVENTS_DIR/$TARGET.json"
if [[ "$TARGET" == "start-job" && -f "$EVENTS_DIR/start-job.json" ]]; then
  EVENT_FILE="$EVENTS_DIR/start-job.json"
fi
if [[ ! -f "$EVENT_FILE" ]]; then
  echo "ERROR: No test event at $EVENT_FILE"
  echo "Create one and re-run."
  exit 1
fi

echo "==> Testing $FUNCTION_NAME with event: $EVENT_FILE"
echo ""

# ─── Quick Python test (no Docker required) ──────────────────────────────────
# If --no-docker is passed, just run the handler directly with Python.
if [[ "${2:-}" == "--no-docker" ]]; then
  echo "==> Running directly with Python (no Docker)..."
  echo ""

  # Use the frontend venv if available (has boto3)
  PYTHON="python3"
  VENV_PYTHON="$SCRIPT_DIR/../frontend/.venv/bin/python3"
  if [[ -f "$VENV_PYTHON" ]]; then
    PYTHON="$VENV_PYTHON"
  fi

  # Set up the PYTHONPATH so shared/ is importable
  export PYTHONPATH="$SCRIPT_DIR/lambda:${PYTHONPATH:-}"
  export JOBS_TABLE="TruffleJobs"
  export RESULTS_BUCKET="truffle-results-test"
  export EXTERNAL_ID="test-external-id"
  export POLICY_SCAN_SM_ARN="arn:aws:states:us-east-1:123456789012:stateMachine:test"
  export IAM_DISCOVER_SM_ARN="arn:aws:states:us-east-1:123456789012:stateMachine:test"
  export IAM_MIGRATE_SM_ARN="arn:aws:states:us-east-1:123456789012:stateMachine:test"
  export MIGRATION_LOG_TABLE="TruffleMigrationLog"

  "$PYTHON" -c "
import json, sys
sys.path.insert(0, '$SCRIPT_DIR/lambda/$TARGET')
sys.path.insert(0, '$SCRIPT_DIR/lambda')
import handler
with open('$EVENT_FILE') as f:
    event = json.load(f)
try:
    result = handler.lambda_handler(event, None)
    print(json.dumps(result, indent=2, default=str))
except Exception as e:
    print(f'ERROR: {type(e).__name__}: {e}', file=sys.stderr)
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
  exit $?
fi

# ─── SAM local invoke (Docker) ───────────────────────────────────────────────
echo "==> Using SAM CLI (requires Docker)..."
sam local invoke "$FUNCTION_NAME" \
  --template "$TEMPLATE" \
  --event "$EVENT_FILE" \
  --env-vars <(echo '{
    "'$FUNCTION_NAME'": {
      "JOBS_TABLE": "TruffleJobs",
      "RESULTS_BUCKET": "truffle-results-test",
      "EXTERNAL_ID": "test-external-id",
      "POLICY_SCAN_SM_ARN": "arn:aws:states:us-east-1:123456789012:stateMachine:test",
      "IAM_DISCOVER_SM_ARN": "arn:aws:states:us-east-1:123456789012:stateMachine:test",
      "IAM_MIGRATE_SM_ARN": "arn:aws:states:us-east-1:123456789012:stateMachine:test",
      "MIGRATION_LOG_TABLE": "TruffleMigrationLog"
    }
  }')
