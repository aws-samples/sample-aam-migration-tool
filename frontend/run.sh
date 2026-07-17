#!/usr/bin/env bash
#
# run.sh — one-command setup + launch for the Truffle local console.
#
# Usage:
#   ./run.sh                             Local mode (default)
#   ./run.sh --managed --endpoint URL    Managed mode (backend in AWS)
#   ./run.sh --rebuild                   Force a fresh frontend build before serving.
#   ./run.sh --dev                       Dev mode: Flask API (:5000) + Vite hot-reload (:5173).
#
# Options:
#   --managed              Use the managed AWS backend instead of local execution
#   --endpoint URL         API Gateway endpoint (required with --managed)
#   --region REGION        Override the API region (auto-detected from endpoint if omitted)
#   --profile PROFILE      AWS profile for signing API requests
#   --dev                  Run in dev mode (Flask + Vite)
#   --rebuild              Force frontend rebuild
#
# All steps are idempotent — safe to re-run.

set -euo pipefail

# Always operate from the frontend/ directory (where this script lives).
cd "$(dirname "$0")"

MODE="serve"
TRUFFLE_MODE="${TRUFFLE_MODE:-local}"
TRUFFLE_API_ENDPOINT="${TRUFFLE_API_ENDPOINT:-}"
TRUFFLE_API_REGION="${TRUFFLE_API_REGION:-}"
TRUFFLE_API_PROFILE="${TRUFFLE_API_PROFILE:-}"
TRUFFLE_IDC_REGION="${TRUFFLE_IDC_REGION:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)       MODE="dev"; shift ;;
    --rebuild)   MODE="rebuild"; shift ;;
    --managed)   TRUFFLE_MODE="managed"; shift ;;
    --local)     TRUFFLE_MODE="local"; TRUFFLE_API_ENDPOINT=""; shift ;;
    --endpoint)  TRUFFLE_API_ENDPOINT="$2"; shift 2 ;;
    --api-region) TRUFFLE_API_REGION="$2"; shift 2 ;;
    --region)    TRUFFLE_IDC_REGION="$2"; shift 2 ;;
    --profile)   TRUFFLE_API_PROFILE="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Validate managed mode requirements
if [[ "$TRUFFLE_MODE" == "managed" && -z "$TRUFFLE_API_ENDPOINT" ]]; then
  echo "ERROR: --endpoint is required with --managed" >&2
  echo "Usage: ./run.sh --managed --endpoint https://<id>.execute-api.<region>.amazonaws.com/prod" >&2
  exit 1
fi

export TRUFFLE_MODE
export TRUFFLE_API_ENDPOINT
export TRUFFLE_API_REGION
export TRUFFLE_API_PROFILE
export TRUFFLE_IDC_REGION

# ─── Prerequisite checks ─────────────────────────────────────────────────────
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }
command -v npm >/dev/null     || { echo "npm (Node.js) is required." >&2; exit 1; }

# ─── Backend setup (idempotent) ──────────────────────────────────────────────
if [[ ! -d .venv ]]; then
  echo "==> Creating Python virtualenv (.venv)"
  python3 -m venv .venv
fi
echo "==> Installing Python dependencies"
.venv/bin/pip install -q -r requirements.txt

# ─── Frontend setup (idempotent) ─────────────────────────────────────────────
if [[ ! -d web/node_modules ]]; then
  echo "==> Installing frontend dependencies (npm install)"
  (cd web && npm install --no-fund --no-audit)
fi

# ─── Launch ──────────────────────────────────────────────────────────────────
if [[ "$TRUFFLE_MODE" == "managed" ]]; then
  echo "==> Mode: MANAGED (backend: $TRUFFLE_API_ENDPOINT)"
else
  echo "==> Mode: LOCAL (all scans run on this machine)"
fi
if [[ -n "$TRUFFLE_IDC_REGION" ]]; then
  echo "==> IdC/AAM Region: $TRUFFLE_IDC_REGION"
fi

if [[ "$MODE" == "dev" ]]; then
  echo "==> Dev mode: starting Flask API and Vite dev server"
  # Start Flask in the background; ensure it's killed when this script exits.
  .venv/bin/python app.py &
  FLASK_PID=$!
  trap 'kill "$FLASK_PID" 2>/dev/null || true' EXIT
  echo "    Flask API:  http://127.0.0.1:5000  (pid $FLASK_PID)"
  echo "    Open the Vite URL printed below for hot reload."
  (cd web && npm run dev)
  exit 0
fi

# serve / rebuild modes: build the static UI, then serve it from Flask.
if [[ "$MODE" == "rebuild" || ! -d web/dist ]]; then
  echo "==> Building frontend (npm run build)"
  (cd web && npm run build)
fi

echo "==> Serving at http://127.0.0.1:5000  (Ctrl+C to stop)"
exec .venv/bin/python app.py
