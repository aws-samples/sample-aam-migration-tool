# Truffle — Local Migration Console

A locally-run web console for the Account Access Manager (AAM) migration tool.
It uses the [Cloudscape Design System](https://cloudscape.design/) — the same
design system the AWS Console is built from — so it looks and feels like a
native AWS service console, while running entirely on your machine against your
local AWS credential chain.

## Architecture

- **Backend** — a small Flask JSON API (`app.py` + `backend/`). The only web
  dependency is Flask; boto3 is already required by the utilities.
- **Frontend** — a Cloudscape + React app built with Vite (`web/`). Heavier to
  install/build than hand-rolled HTML, but it delivers the authentic AWS
  console look/feel and ships accessible, virtualized tables that stay
  responsive on large permission-set / role lists. The production build is
  static files served locally by Flask, so runtime stays light.
- **Cache** — results (policy scans, permission-set dumps, federation configs)
  are written to local files under `cache/` and re-read on load, per the design
  tenets.

## Layout

```
frontend/
├── app.py                 # Flask entry point + JSON API + serves built UI
├── requirements.txt
├── backend/               # Python backend modules
│   ├── config.py          # paths / cache locations
│   ├── cache.py           # local-file cache helpers
│   ├── aws_session.py     # credential-profile / session helpers
│   ├── policy_analysis.py # WIRED to Utilites/resource_policy_scan
│   ├── iam_federation.py  # SKELETON — to be implemented
│   └── idc.py             # SKELETON — to be implemented
├── web/                   # Cloudscape + React + Vite frontend (see web/README.md)
│   └── src/pages/         # one page per tab
└── cache/                 # local cache output (git-ignored)
```

## Feature status

| Tab | Status |
|---|---|
| Policy Analysis | **Wired** to `scan_resource_policies.py` (parallel accounts, background job with live progress, resumable via checkpoints) |
| IAM Federation → AAM | Skeleton / UI outline only |
| IdC → AAM | Skeleton / UI outline only |
| Cache | View cache age/size/contents and clear entries |

## Running

### 1. Backend (Flask API)

```bash
cd frontend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 app.py                      # http://127.0.0.1:5000
```

### 2. Frontend

For development with hot reload (separate terminal):

```bash
cd frontend/web
npm install
npm run dev                         # http://127.0.0.1:5173  (proxies /api to Flask)
```

To serve the built UI directly from Flask instead:

```bash
cd frontend/web
npm install
npm run build                       # emits web/dist/
# then open http://127.0.0.1:5000
```

## Notes

- The console reads available profiles from your AWS config. Operations use
  whatever credentials those profiles resolve to — prefer ReadOnly / least
  privilege profiles for discovery and analysis.
- **Scans run as background jobs.** `POST /api/policy-analysis/scan` returns a
  `job_id`; the UI polls `GET /api/policy-analysis/status?job_id=…` (~1s) for a
  progress bar and the final result. Accounts are scanned in parallel.
- **Scans are resumable.** Each completed unit (per account, and per
  account+region) is checkpointed under `cache/checkpoints/`, keyed by the scan
  parameters. If a scan is interrupted (crash, server restart, a throttled
  region), re-running the same scan skips the units that already finished.
  Checkpoints older than 24h are treated as stale and re-scanned, and a
  checkpoint is deleted once a scan completes fully — so a deliberate re-run
  after success starts fresh.
- Migration actions (trust-policy updates, role creation, CloudFormation
  generation) are **not implemented yet**; those tabs render the intended
  workflow only and the corresponding API endpoints return `501 Not Implemented`.
```
