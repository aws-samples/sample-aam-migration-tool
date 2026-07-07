#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Validate Step Functions state machine definitions against the AWS API.
#
# Uses the `aws stepfunctions validate-state-machine-definition` API which
# checks ASL syntax, JSONPath expressions, intrinsic functions, and resource
# references without actually creating anything.
#
# Usage:
#   ./validate-state-machines.sh
#   ./validate-state-machines.sh --profile my-profile
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SM_DIR="$SCRIPT_DIR/state-machines"
PROFILE_ARG=""

for arg in "$@"; do
  if [[ "$arg" == "--profile" ]]; then
    PROFILE_ARG="--profile"
  elif [[ -n "$PROFILE_ARG" && "$PROFILE_ARG" == "--profile" ]]; then
    PROFILE_ARG="--profile $arg"
  fi
done

ERRORS=0

echo "Validating Step Functions state machine definitions..."
echo ""

for file in "$SM_DIR"/*.asl.json; do
  filename=$(basename "$file")
  echo -n "  $filename ... "

  # Replace CDK substitution placeholders with dummy ARNs so the validator
  # doesn't reject them. The real values are injected by CDK at deploy time.
  DEFINITION=$(cat "$file" \
    | sed 's|\${ScanUnitFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${ScanGlobalFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${AggregateFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${DiscoverRolesFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${MigrateRoleFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${IdcDiscoverFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${IdcApplyFnArn}|arn:aws:lambda:us-east-1:123456789012:function:placeholder|g' \
    | sed 's|\${JobsTableName}|TruffleJobs|g' \
    | sed 's|\${MigrationLogTableName}|TruffleMigrationLog|g' \
  )

  RESULT=$(echo "$DEFINITION" | aws stepfunctions validate-state-machine-definition \
    --type STANDARD \
    --definition "$(echo "$DEFINITION")" \
    $PROFILE_ARG \
    --output json 2>&1) || true

  # Check for validation errors
  DIAG_COUNT=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    diags = data.get('diagnostics', [])
    errors = [d for d in diags if d.get('severity') == 'ERROR']
    print(len(errors))
except:
    print('-1')
" 2>/dev/null)

  if [[ "$DIAG_COUNT" == "0" ]]; then
    echo "OK"
  elif [[ "$DIAG_COUNT" == "-1" ]]; then
    echo "FAILED (API error)"
    echo "    $RESULT" | head -5
    ERRORS=$((ERRORS + 1))
  else
    echo "FAILED ($DIAG_COUNT error(s))"
    echo "$RESULT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('diagnostics', []):
    if d.get('severity') == 'ERROR':
        print(f\"    [{d.get('code','?')}] {d.get('message','')}\")
" 2>/dev/null
    ERRORS=$((ERRORS + 1))
  fi
done

echo ""
if [[ $ERRORS -gt 0 ]]; then
  echo "VALIDATION FAILED: $ERRORS state machine(s) have errors."
  exit 1
else
  echo "All state machines validated successfully."
  exit 0
fi
