#!/usr/bin/env bash
#
# run.sh — one-command setup + launch for the Truffle local console.
#
# Usage:
#   ./run.sh              First-time setup (venv, pip, npm), build the UI,
#                         then serve everything from Flask at :5000.
#   ./run.sh --rebuild    Force a fresh frontend build before serving.
#   ./run.sh --dev        Dev mode: Flask API (:5000) + Vite hot-reload (:5173).
#
# All steps are idempotent — safe to re-run.

set -euo pipefail

# Always operate from the frontend/ directory (where this script lives).
cd "$(dirname "$0")"

MODE="serve"
for arg in "$@"; do
  case "$arg" in
    --dev)     MODE="dev" ;;
    --rebuild) MODE="rebuild" ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

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
