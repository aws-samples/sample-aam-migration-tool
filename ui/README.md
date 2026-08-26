# AAM Migration Console

A locally-run web console for migrating to AWS [Account Access Manager (AAM)](https://docs.aws.amazon.com/IAM/latest/UserGuide/account-access-manager.html).
Built with the [Cloudscape Design System](https://cloudscape.design/) for an
authentic AWS Console look and feel, running entirely on your machine.

### Reference documentation

| Topic | AWS documentation |
|-------|-------------------|
| Account Access Manager (AAM) | [Overview](https://docs.aws.amazon.com/IAM/latest/UserGuide/account-access-manager.html) · [Getting started (create/enable the application)](https://docs.aws.amazon.com/IAM/latest/UserGuide/account-access-manager-getting-started.html) |
| AAM application & entitlements (API) | [`CreateApplication`](https://docs.aws.amazon.com/account-access/latest/APIReference/API_CreateApplication.html) · [`CreateEntitlement`](https://docs.aws.amazon.com/account-access/latest/APIReference/API_CreateEntitlement.html) |
| IAM Identity Center (IdC) | [What is IAM Identity Center?](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html) |
| SAML-based IAM federation | [SAML 2.0 federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html) |
| IAM role trust policies | [Custom trust policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-custom.html) |

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | >= 3.11 | For the Flask backend |
| Node.js | >= 18 | For building the React UI |
| npm | any recent | Comes with Node |
| AWS CLI | v2 | For credential resolution and AAM commands |
| AWS credentials | configured | SSO, profiles, or environment variables |


## Quick Start

```bash
cd ui
./run.sh
```

This handles everything: creates a virtualenv, installs dependencies, builds
the React UI, and serves at **http://127.0.0.1:5000**.

### Run Script Options

```bash
./run.sh                       # Local mode (default)
./run.sh --dev                 # Dev mode: Flask + Vite hot-reload
./run.sh --rebuild             # Force UI rebuild

```

| Flag | Required | Description |
|------|----------|-------------|
| `--region REGION` | No | AWS region for API signing (auto-detected from endpoint URL) |
| `--profile PROFILE` | No | AWS profile for signing managed API requests |
| `--dev` | No | Dev mode with Vite hot-reload on :5173 |
| `--rebuild` | No | Force a fresh UI build |

---

## Features

### 1. Policy Analysis (Resource Policy Scanner)

Scans resource policies across one or more AWS accounts looking for references
to specific strings (e.g., an old SAML provider ARN you're migrating away from).

**What you need to provide:**
- **Search terms** — one or more strings to search for in resource policies
- **Authentication** — choose between (single or multi-account scans):
  - *Local profiles* — select one or more AWS credential profiles
  - *Assume role* — provide account IDs + a role name to assume in each
- **Regions** — which regions to scan (default: all enabled regions)
- **Services** — optionally filter to specific services (S3, SQS, KMS, etc.)
- **Management account** — check this if scanning the Org management account (enables SCP/RCP scanning)

### 2. IAM Federation → AAM

Discovers IAM roles with [SAML trust policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html) and migrates them to AAM.

**Step 1: Discovery** — what you need:
- **Authentication** — same options as Policy Analysis
- **IDP ARN** — the SAML provider ARN to search for (e.g., `arn:aws:iam::123456789012:saml-provider/Okta`)

**Step 2: Migration** — what you need:
- **Mode** — `ADD` (keep existing trust, add AAM) or `REPLACE` (remove old SAML trust, add AAM)
- **Role selection** — which discovered roles to migrate
- **AAM Application ARN** — required for creating entitlements. Get it with:
  ```bash
  aws account-access list-applications --region <region>
  ```
  Copy the `applicationArn` from the output.
- **Include sts:TagSession in trust policy** (checkbox, in the AAM Configuration panel) — **checked by default.** Allows AAM to pass session tags when assuming the role. Uncheck it only if you do not need or want the ability for roles to leverage session tags. The choice applies to both live trust policy updates and generated IaC.

### 3. IdC → AAM

Inventories [Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html) permission sets and assignments, then creates
equivalent IAM roles with AAM [trust policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-custom.html) and [entitlements](https://docs.aws.amazon.com/account-access/latest/APIReference/API_CreateEntitlement.html).

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
  aws account-access list-applications --region <region>
  ```
  Copy the `applicationArn` from the output.
- **Role path** — IAM path for created roles (default: `/aam/`)
- **Permission set selection** — which permission sets to create roles for
- **Include sts:TagSession in trust policy** (checkbox, in the AAM Configuration panel) — **checked by default.** Allows AAM to pass session tags when assuming the role. Uncheck it only if you do not need or want the ability for roles to leverage session tags. The choice applies to both live role creation (apply) and generated IaC.

### CSV Upload Formats

Both tools support uploading a CSV to define mappings directly (skip or supplement discovery).

**IdC Migration Plan CSV** — upload in the migration plan section. See [Identity Center to AAM README — Migration plan CSV format](../Identity%20Center%20to%20AAM/README.md#migration-plan-csv-format) for the full column reference.

Required columns: `Permission Set ARN`, `Role Name`, `Account ID`, `Principal`. Column order does not matter.

**IAM Federation Entitlement CSV** — upload in the entitlement mapping section. See [IAM Federation README — Columnar CSV](../IAM%20Federation%20to%20AAM/README.md#columnar-csv-recommended) for the full column reference.

Required columns: `Group/Principal`, `Account ID`, `Role Name`. Column order does not matter.

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
aws account-access list-applications --region <region>
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
| IdC Apply (entitlements) | `account-access:CreateEntitlement` |

---

## Architecture

```
ui/
├── run.sh                    # One-command launcher
├── app.py                    # Flask entry point + JSON API + serves built UI
├── requirements.txt          # Python dependencies (includes custom boto3 wheels)
├── backend/                  # Python backend modules
│   ├── config.py             # Paths, cache locations, execution mode config
│   ├── cache.py              # Local-file cache helpers
│   ├── checkpoint.py         # Scan resume/checkpoint logic
│   ├── aws_session.py        # Credential-profile / session helpers
│   ├── jobs.py               # Job dispatcher
│   ├── _jobs_local.py        # Local execution (threads, in-process scanning)
│   ├── policy_analysis.py    # Resource policy scanning logic
│   ├── iam_federation.py     # IAM federation discovery + migration
│   └── idc.py                # IdC discovery + apply
├── web/                      # Cloudscape + React + Vite UI
│   └── src/pages/            # One page per feature tab
└── cache/                    # Local cache output (git-ignored)
```

---

## Troubleshooting

### "No module named 'botocore'" or "'boto3'"
Run `pip install -r requirements.txt` from the `ui/` directory, or use
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
restart Flask.
