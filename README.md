# Truffle — AAM Migration Toolkit

A local-first toolkit that helps customers migrate to **AWS Account Access Manager (AAM)** from IAM Identity Center (IdC) or SAML-based IAM Federation. It automates discovery, policy analysis, role creation, and entitlement mapping — all from a browser-based console running on your local machine.

---

## Quick Start

```bash
cd frontend
./run.sh          # First run: sets up venv, installs deps, builds UI, starts at http://127.0.0.1:5000
./run.sh --dev    # Development: Flask API + Vite hot-reload
./run.sh --rebuild  # Force frontend rebuild
```

**Requirements:** Python 3.11+, Node.js 18+, AWS credentials configured locally.

---

## What's Included

The toolkit provides three integrated tools accessible from a single browser-based console:

### 1. Policy Analysis

**What it does:** Scans resource-based policies (S3, KMS, SQS, SNS, Lambda, etc.), IAM trust policies, and Organization policies (SCPs/RCPs) across your accounts for specific search strings.

**Why you need it:** Before migrating to AAM, you need to identify every policy that references your current identity provider — SAML provider ARNs, Identity Center role ARNs, or specific principal identifiers. These policies may need updates after migration.

**What it finds:**
- Resource-based policies containing your search terms
- IAM role trust policies referencing your IdP
- Organization SCPs and RCPs (requires management/delegated-admin credentials)

**What it does NOT do:**
- It does not modify any policies — it is strictly read-only
- It does not analyze VPC endpoint policies (future work)
- It does not recommend which policies to change — that requires human judgment based on your migration strategy

---

### 2. IAM Federation → AAM

**What it does:** Discovers SAML-federated IAM roles in your accounts and updates their trust policies to add (or replace with) the AAM service principal, enabling AAM to assume those roles.

**Why you need it:** If you currently use SAML-based federation (Okta, Microsoft Entra ID, OneLogin, etc.) to grant AWS access, those IAM roles trust your external identity provider. For AAM to manage access to those same roles, the trust policies must include AAM's service principal.

**What it changes in your environment:**
- **Discovery phase:** Read-only. Lists SAML providers and IAM roles.
- **Migration phase (ADD mode):** Appends a new trust policy statement for AAM alongside the existing SAML trust. The SAML trust remains functional — both access paths work simultaneously.
- **Migration phase (REPLACE mode):** Removes the SAML trust statement and replaces it with the AAM trust. After this, only AAM can assume the role.
- **IaC generation:** Writes CloudFormation and Terraform templates locally. No AWS changes.

**What it does NOT do:**
- It does not create new IAM roles — it only modifies trust policies on existing roles
- It does not create the AAM application — that is an operator prerequisite
- It does not update resource-based policies that reference the federated roles
- It does not handle rollback automatically — but it records original trust policies for manual rollback

---

### 3. IdC → AAM

**What it does:** Inventories your Identity Center permission sets and account assignments, then recreates them as IAM roles with the AAM trust policy — either as CloudFormation templates or directly via the API. AAM entitlements that preserve who-can-access-what are generated alongside the roles.

**Why you need it:** Customers migrate from IdC to AAM when they hit IdC quota limits (500 permission sets, 20 TPS API throttle), need high permission-set-per-account ratios (e.g., EKS workloads), or want AAM-specific features not available in IdC.

**What it changes in your environment:**
- **Discovery phase:** Read-only. Inventories permission sets, policies, and assignments via IdC APIs.
- **Generate-IaC mode (default):** Writes CloudFormation templates locally. No AWS changes.
- **Apply mode:** Creates IAM roles in target accounts and optionally creates AAM entitlements. This is the only mode that mutates your environment.

**What it does NOT do:**
- It does not delete or modify your existing IdC permission sets or assignments
- It does not create the AAM application — that is an operator prerequisite
- It does not disable IdC after migration — you run both in parallel until ready to cut over
- It does not handle customer managed policies that don't exist in the target account — those must be pre-created with the same name and path
- It does not migrate permission set session duration settings to the IAM role (IAM roles use their own max session duration)

---

## Prerequisites

| Prerequisite | Required for | Notes |
|-------------|-------------|-------|
| AWS credentials (local) | All tools | Environment variables, named profiles, or `aws login` |
| IAM read permissions | Policy Analysis, IAM Fed discovery, IdC discovery | `iam:List*`, `iam:Get*`, `sts:GetCallerIdentity` |
| IdC read permissions | IdC discovery | `sso:List*`, `sso:Describe*`, `sso:Get*`, `identitystore:Describe*` |
| IAM write permissions | IAM Fed migration, IdC apply mode | `iam:UpdateAssumeRolePolicy` (Fed), `iam:CreateRole`, `iam:AttachRolePolicy`, `iam:PutRolePolicy` (IdC) |
| AAM application | IdC entitlements | Create this manually before using the tool. The tool never creates applications. |
| Custom boto3 wheels | AAM entitlement creation (apply mode) | Preview SDK — see installation below. Not needed for generate-iac mode. |
| Cross-account role | Multi-account scanning | A role in each target account that your credentials can assume |

---

## Installation

```bash
cd frontend
./run.sh   # Handles everything: venv, pip install, npm install, build, serve
```

The `run.sh` script is idempotent — safe to re-run. It installs:
- Python dependencies including the custom AAM-aware boto3/botocore wheels (from the repo root)
- Node.js frontend dependencies
- Builds the React/Cloudscape UI

---

## Authentication Modes

Every tool supports three operating modes:

| Mode | How it works | When to use |
|------|-------------|-------------|
| **Single account** | Uses your default AWS credential chain | Migrating one account at a time |
| **Multi-account** | Named profiles (one per account) or AssumeRole with account IDs + role name | Migrating a specific set of accounts |
| **Entire organization** | Scans all provisioned accounts in IdC | Full inventory before planning a migration |

For multi-account with AssumeRole: your default credentials must have `sts:AssumeRole` permission for the specified role in each target account.

---

## What the Customer Must Do (Not Handled by This Tool)

1. **Create the AAM application** — The tool creates entitlements *against* an application but never creates the application itself.
2. **Pre-create customer managed policies** — If your IdC permission sets reference customer managed policies, those policies must exist in each target account with the same name and path before roles are created.
3. **Test access after migration** — Validate that users/groups can assume the new roles and that permissions are equivalent.
4. **Run parallel operations** — Keep IdC or SAML federation active alongside AAM until you've validated the migration.
5. **Decommission legacy access** — Once satisfied, disable the old access path (delete IdC assignments or remove SAML trust statements).
6. **Update resource-based policies** — If any S3 bucket policies, KMS key policies, etc. reference your old IdC role ARNs, update them to reference the new AAM role ARNs. The Policy Analysis tool helps identify these.
7. **Set up break-glass access** — Ensure emergency access procedures (IAM users or direct federation) exist before cutting over.
8. **Create Entitlements for IAM Federation -> AAM** - For this tool, it will only update the trust policy for the in-scope roles. Since entitlements aren't stored in a standard place in AWS, these need to re-created using either the AAM console or API. 

---

## Caveats and Limitations

- **Local-only execution.** The tool runs entirely on your machine. No data is sent to any external service. Results are cached in `frontend/cache/`.
- **No rollback automation.** If you use apply mode and need to undo, you must manually revert (delete roles, restore trust policies from the backup). The tool logs what it changed but does not provide a one-click undo.
- **IdC API throttling.** In organization-wide scans, you may hit IdC API rate limits (20 TPS). The tool uses exponential backoff but large orgs will take longer.
- **Inline policy size limits.** IAM roles have a 10,240-character limit for inline policies. If your IdC permission set has a larger inline policy, the CreateRole call will fail — convert to a customer managed policy instead (the CLI tool supports `--convert-inline-to-cmp`).
- **Permission boundary propagation.** If your IdC permission sets have permission boundaries, the referenced policy must exist in the target account.
- **AAM preview SDK.** The AAM API is in preview. The custom boto3 wheels are required for live entitlement creation. Generate-IaC mode works with standard boto3.

---

## Architecture

- **Frontend:** React + Cloudscape (AWS design system), built with Vite
- **Backend:** Flask (Python), serving both the API and the built SPA
- **Execution:** All AWS API calls run locally using your credential chain
- **Caching:** Results cached to local JSON files in `frontend/cache/`
- **Checkpointing:** Policy analysis scans checkpoint per-unit so interrupted scans resume

For the managed serverless deployment architecture, see `managed solution/ARCHITECTURE.md`.

---

## Repository Structure

```
truffle/
├── frontend/                         # Browser-based console (Flask + React)
│   ├── app.py                        # Flask API server
│   ├── backend/                      # Python backend modules
│   │   ├── policy_analysis.py        # Policy scan adapter
│   │   ├── iam_federation.py         # IAM Federation adapter
│   │   ├── idc.py                    # IdC-to-AAM adapter
│   │   ├── aws_session.py            # Credential/session helpers
│   │   ├── jobs.py                   # Background job runner
│   │   ├── cache.py                  # Local file caching
│   │   ├── checkpoint.py             # Scan resume support
│   │   └── config.py                 # Path configuration
│   ├── web/                          # React/Cloudscape frontend
│   │   └── src/pages/                # Tool UI pages
│   ├── cache/                        # Local cached results (gitignored)
│   ├── run.sh                        # One-command setup + launch
│   └── requirements.txt              # Python dependencies
├── IAM Federation to AAM/            # Standalone CLI tool
│   ├── AAM_role_evaluation.py        # Discovery + trust policy migration
│   └── generate_iac_templates.py     # CloudFormation/Terraform generation
├── Identity Center to AAM/           # Standalone CLI tool
│   ├── idc_to_aam.py                 # Main orchestrator
│   ├── inventory.py                  # IdC discovery (optimized per-account)
│   ├── role_creator.py               # IAM role creation
│   ├── entitlement_creator.py        # AAM entitlement creation
│   ├── iac_generator.py              # CloudFormation generation (per-account)
│   └── tests/                        # Unit + property-based tests
├── Utilites/                         # Shared utilities
│   └── resource_policy_scan/         # Resource policy scanner
├── managed solution/                 # Serverless deployment architecture
│   └── ARCHITECTURE.md               # Design doc (API GW, Lambda, Step Functions)
└── README.md                         # This file
```

---

## Design Tenets

- **Lightweight.** Minimal dependencies. No Docker, no containers, no cloud infrastructure required.
- **Fast.** Parallel API calls, per-unit checkpointing, incremental progress reporting.
- **AWS console look and feel.** Uses [Cloudscape](https://cloudscape.design/) — the same design system as the AWS Console.
- **Local-first.** Runs on your machine, uses your credentials, caches results to local files. No data leaves your environment.
- **Safe by default.** Generate-IaC mode (read-only) is the default. Apply mode requires explicit action and shows confirmation warnings.
