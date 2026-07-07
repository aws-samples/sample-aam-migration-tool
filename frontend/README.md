# Truffle — AAM Migration Console

A locally-run web console for migrating to AWS Account Access Manager (AAM).
Built with the [Cloudscape Design System](https://cloudscape.design/) for an
authentic AWS Console look and feel, running entirely on your machine.

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | >= 3.11 | For the Flask backend |
| Node.js | >= 18 | For building the React frontend |
| npm | any recent | Comes with Node |
| AWS CLI | v2 | For credential resolution and AAM commands |
| AWS credentials | configured | SSO, profiles, or environment variables |

### Custom boto3 SDK (required)

The tool uses a preview version of boto3/botocore that includes the AAM
(`accountaccess`) service model. The `.whl` files are in the repo root and
are installed automatically by `pip install -r requirements.txt`.

Once the AAM service launches publicly, the standard boto3 will work and
these wheels can be removed.

---

## Quick Start

```bash
cd frontend
./run.sh
```

This handles everything: creates a virtualenv, installs dependencies, builds
the React UI, and serves at **http://127.0.0.1:5000**.

### Run Script Options

```bash
./run.sh                       # Local mode (default)
./run.sh --dev                 # Dev mode: Flask + Vite hot-reload
./run.sh --rebuild             # Force frontend rebuild

# Managed backend mode (requires deployed infrastructure)
./run.sh --managed --endpoint https://<id>.execute-api.<region>.amazonaws.com/prod
./run.sh --managed --endpoint URL --profile my-aws-profile
./run.sh --managed --endpoint URL --region us-west-2
```

| Flag | Required | Description |
|------|----------|-------------|
| `--managed` | No | Use the managed AWS backend instead of local execution |
| `--endpoint URL` | Yes (with `--managed`) | API Gateway endpoint from CDK deploy output |
| `--region REGION` | No | AWS region for API signing (auto-detected from endpoint URL) |
| `--profile PROFILE` | No | AWS profile for signing managed API requests |
| `--dev` | No | Dev mode with Vite hot-reload on :5173 |
| `--rebuild` | No | Force a fresh frontend build |

Environment variables also work: `TRUFFLE_MODE`, `TRUFFLE_API_ENDPOINT`,
`TRUFFLE_API_REGION`, `TRUFFLE_API_PROFILE`.

---

## Features

### 1. Policy Analysis (Resource Policy Scanner)

Scans resource policies across one or more AWS accounts looking for references
to specific strings (e.g., an old SAML provider ARN you're migrating away from).

**What you need to provide:**
- **Search terms** — one or more strings to search for in resource policies
- **Authentication** — choose between:
  - *Local profiles* — select one or more AWS credential profiles
  - *Assume role* — provide account IDs + a role name to assume in each
- **Regions** — which regions to scan (default: all enabled regions)
- **Services** — optionally filter to specific services (S3, SQS, KMS, etc.)
- **Management account** — check this if scanning the Org management account (enables SCP/RCP scanning)

### 2. IAM Federation → AAM

Discovers IAM roles with SAML trust policies and migrates them to AAM.

**Step 1: Discovery** — what you need:
- **Authentication** — same options as Policy Analysis
- **IDP ARN** — the SAML provider ARN to search for (e.g., `arn:aws:iam::123456789012:saml-provider/Okta`)

**Step 2: Migration** — what you need:
- **Mode** — `ADD` (keep existing trust, add AAM) or `REPLACE` (remove old SAML trust, add AAM)
- **Role selection** — which discovered roles to migrate

### 3. IdC → AAM

Inventories Identity Center permission sets and assignments, then creates
equivalent IAM roles with AAM trust policies and entitlements.

**Step 1: Discovery** — what you need:
- **Region** — the region where Identity Center is configured (check your IdC console)
- **Account scope**:
  - *Single* — scan one account's provisioned permission sets
  - *Multi* — scan specific account IDs
  - *Org* — scan all permission sets in the organization
- **Target account IDs** — the management account or delegated admin account ID for IdC
- **Authentication** — credentials with access to the IdC management/delegated admin account

**Step 2: Apply** — what you need:
- **AAM Application ARN** — required for creating entitlements. Get it with:
  ```bash
  aws account-access-preview list-applications --region <region>
  ```
  Copy the `applicationArn` from the output.
- **Role path** — IAM path for created roles (default: `/aam/`)
- **Permission set selection** — which permission sets to create roles for

---

## Important Notes

### Identity Center Region

Identity Center is a **single-region** service. You must provide the correct
region where your IdC instance is configured. This is NOT necessarily
`us-east-1`. Check the Identity Center console to find your region.

### AAM Application ARN

The AAM Application ARN is needed for creating entitlements (the mapping
between IdC principals and IAM roles). To find it:

```bash
# Replace <region> with the region where AAM is configured
aws account-access-preview list-applications --region <region>
```

If no applications are listed, you need to create one first through the AAM
console or API.

### Credential Requirements

| Operation | Minimum permissions needed |
|-----------|--------------------------|
| Policy Analysis (scan) | `ReadOnlyAccess` in target accounts |
| IAM Federation (discover) | `iam:ListRoles`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies` |
| IAM Federation (migrate) | `iam:GetRole`, `iam:UpdateAssumeRolePolicy` |
| IdC Discovery | `sso-admin:*`, `identitystore:Describe*`, `identitystore:List*` (from management/delegated admin account) |
| IdC Apply (create roles) | `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:TagRole` |
| IdC Apply (entitlements) | `account-access-preview:CreateEntitlement` |

### Local Mode vs Managed Mode

| | Local Mode | Managed Mode |
|---|---|---|
| How it works | Scans run directly on your machine using local AWS creds | Jobs submitted to a serverless backend in AWS |
| When to use | Small-scale (few accounts), testing, development | Large-scale (100s of accounts), long-running scans |
| Setup | Just `./run.sh` | Deploy the managed solution first (see `managed solution/README.md`) |
| Credentials | Your local AWS profiles/SSO | Local creds sign the API request; backend assumes into target accounts |

---

## Architecture

```
frontend/
├── run.sh                    # One-command launcher
├── app.py                    # Flask entry point + JSON API + serves built UI
├── requirements.txt          # Python dependencies (includes custom boto3 wheels)
├── backend/                  # Python backend modules
│   ├── config.py             # Paths, cache locations, execution mode config
│   ├── cache.py              # Local-file cache helpers
│   ├── checkpoint.py         # Scan resume/checkpoint logic
│   ├── aws_session.py        # Credential-profile / session helpers
│   ├── jobs.py               # Job dispatcher (routes to local or managed)
│   ├── _jobs_local.py        # Local execution (threads, in-process scanning)
│   ├── _jobs_managed.py      # Managed execution (SigV4 client to API Gateway)
│   ├── policy_analysis.py    # Resource policy scanning logic
│   ├── iam_federation.py     # IAM federation discovery + migration
│   └── idc.py                # IdC discovery + apply
├── web/                      # Cloudscape + React + Vite frontend
│   └── src/pages/            # One page per feature tab
└── cache/                    # Local cache output (git-ignored)
```

---

## Troubleshooting

### "No module named 'botocore'" or "'boto3'"
Run `pip install -r requirements.txt` from the `frontend/` directory, or use
`./run.sh` which handles this automatically.

### "No IAM Identity Center instance found"
You're scanning from the wrong account or region. IdC APIs only work from the
management account or delegated admin account, in the specific region where
IdC is configured.

### "AccessDenied" on scans
Check that your credentials have the required permissions (see table above).
For assume-role mode, verify the target role exists and trusts your caller.

### UI stuck on "running" with no progress
The job may have failed silently. Check the browser console for errors, or
restart Flask. In managed mode, check the Step Functions execution history
in the AWS Console.
