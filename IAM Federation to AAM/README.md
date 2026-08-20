# IAM Federation → AAM — CLI Tool

Evaluate and migrate SAML-federated IAM roles to AWS Account Access Manager (AAM). This tool discovers roles that trust your SAML identity provider, updates their trust policies to enable AAM, and creates AAM entitlements to preserve who-can-access-what.

This is the standalone CLI. For the browser-based console (recommended for most users), see the [main README](../README.md).

---

## Requirements

- Python 3.11+
- The custom **boto3 / botocore 1.43.69** wheels that expose the
  `accountaccess` (AAM) client. AAM is not yet in public boto3, so these are
  required for the entitlement phase (this will get removed once boto3 is updated).
- AWS credentials for the account(s) containing your SAML-federated roles.

---

## Installation

```bash
cd "IAM Federation to AAM"
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Verify the AAM client is available:

```bash
python -c "import boto3; boto3.client('account-access', region_name='us-east-1'); print('AAM client OK')"
```

---

## Quick Start

```bash
# Single account — discover and generate CSV report
python AAM_role_evaluation.py --workers 5

# Multi-account with profiles
python AAM_role_evaluation.py \
  --account-scope multi \
  --profiles prod-account,dev-account,staging-account \
  --workers 5

# Multi-account with assume-role
python AAM_role_evaluation.py \
  --account-scope multi \
  --account-ids 111111111111,222222222222 \
  --role-name ReadOnlyRole \
  --workers 5

# Apply-only mode (skip discovery, apply from CSV)
python AAM_role_evaluation.py \
  --apply-only \
  --entitlement-csv entitlement_mappings.csv \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --mode ADD \
  --region us-east-1

# Multi-account: discover, update trust policies, and create entitlements (with profiles)
# Discovery runs across all listed accounts; the trust policy prompt and entitlement
# creation then apply per-account. Fill in the generated entitlement_mappings_multi.csv
# (Group/Principal + Principal Type columns) before this run.
python AAM_role_evaluation.py \
  --account-scope multi \
  --profiles prod-account,dev-account,staging-account \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --entitlement-csv entitlement_mappings_multi.csv \
  --region us-east-1 \
  --workers 5

# Multi-account: same as above but assume a role into each target account
python AAM_role_evaluation.py \
  --account-scope multi \
  --account-ids 111111111111,222222222222 \
  --role-name OrganizationAccountAccessRole \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --entitlement-csv entitlement_mappings_multi.csv \
  --region us-east-1 \
  --workers 5

# Multi-account apply-only: skip discovery, update trust + entitlements straight from the CSV.
# Credentials for each account are resolved from --profiles (or --account-ids + --role-name).
# The account ID in each CSV row routes the trust policy update to the right account.
python AAM_role_evaluation.py \
  --apply-only \
  --profiles prod-account,dev-account,staging-account \
  --entitlement-csv entitlement_mappings_multi.csv \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --mode ADD \
  --region us-east-1

# Custom trust statement + omit sts:TagSession
python AAM_role_evaluation.py \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --trust-policy my_trust_statement.json \
  --no-tag-session

# With entitlement creation after discovery (columnar CSV)
python AAM_role_evaluation.py \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --entitlement-csv entitlement_mappings.csv \
  --region us-east-1

# Generate IaC templates (no live changes)
# Step 1: Run discovery to get the role report and entitlement template
python AAM_role_evaluation.py --workers 5

# Step 2: Fill in the generated entitlement_mappings_<account>.csv template,
#          then re-run with --generate-iac to produce CloudFormation templates
#          (uses the discovery CSV — no API calls needed)
python AAM_role_evaluation.py \
  --generate-iac \
  --role-evaluation-csv AAM_role_evaluation_075384444871.csv \
  --entitlement-csv entitlement_mappings_075384444871.csv \
  --aam-application-arn "arn:aws:account-access:us-west-2:075384444871:application/app-id"

# Multi-account: same pattern with the consolidated CSV
python AAM_role_evaluation.py \
  --generate-iac \
  --role-evaluation-csv AAM_role_evaluation_multi.csv \
  --entitlement-csv entitlement_mappings_multi.csv \
  --aam-application-arn "arn:aws:account-access:us-west-2:075384444871:application/app-id"
```

---

## What It Does

1. **Lists SAML identity providers** in the account
2. **Prompts you to select** which provider to evaluate against
3. **Scans all IAM roles** (parallelized) and filters to those with a trust policy referencing the selected provider
4. **Generates a CSV report** with role names, attached policies, and trust policy details
5. **Generates an entitlement mapping template** — pre-filled CSV with Account ID, Role Name, and Role ARN for you to add principals
6. **Offers to update trust policies** — ADD (keep SAML, add AAM) or REPLACE (remove SAML, add AAM only)
7. **Creates AAM entitlements** (optional) from the entitlement mapping CSV
8. **Generates IaC** (optional, `--generate-iac`) — produces per-account CloudFormation templates instead of applying live changes

---

## What It Changes

| Phase | Changes? | What happens |
|-------|----------|-------------|
| Discovery + CSV | No | Read-only. Lists providers and roles. Generates entitlement mapping template. |
| Generate IaC (`--generate-iac`) | No | Produces per-account CloudFormation templates for roles + a separate entitlements template. No AWS changes. |
| Trust policy update (ADD) | Yes | Appends AAM service principal statement. SAML trust remains. |
| Trust policy update (REPLACE) | Yes | Removes SAML trust statement, adds AAM statement. |
| Entitlement creation | Yes | Creates `account-access:Entitlement` resources in the hub account. |
| Rollback | Yes | Restores original trust policies from backup file. |

Before any trust policy modification, the tool creates a timestamped JSON backup for rollback.

---

## Command Reference

```
python AAM_role_evaluation.py [OPTIONS]
python AAM_role_evaluation.py --rollback <backup_file>
```

### Account targeting

| Flag | Default | Description |
|------|---------|-------------|
| `--account-scope` | `single` | `single`: current account. `multi`: use profiles or assume-role into targets. |
| `--account-ids` | — | Comma-separated account IDs (for multi with assume-role). |
| `--role-name` | — | Role to assume in each target (for multi with assume-role). |
| `--profiles` | — | Comma-separated AWS profile names (for multi with profiles). Each resolved to its account via GetCallerIdentity. |
| `--workers` | `5` | Parallel workers for role inspection and migration. |

### Apply-only mode

| Flag | Default | Description |
|------|---------|-------------|
| `--apply-only` | off | Skip discovery. Apply trust policy updates + entitlement creation directly from `--entitlement-csv`. |
| `--mode` | `ADD` | Trust policy update mode: `ADD` (keep SAML, add AAM) or `REPLACE` (remove SAML). |

### IaC generation

| Flag | Default | Description |
|------|---------|-------------|
| `--generate-iac` | off | Generate per-account CloudFormation templates instead of applying changes live. Mutually exclusive with interactive trust policy updates. |
| `--role-evaluation-csv` | — | Path to a previously generated role evaluation CSV (from discovery). Skips re-running discovery when used with `--generate-iac`. |

### Entitlement creation

| Flag | Default | Description |
|------|---------|-------------|
| `--aam-application-arn` | — | AAM application ARN. Required for entitlement creation. |
| `--entitlement-csv` | — | Columnar CSV with Group/Principal, Principal Type, Account ID, Role Name, Role ARN columns. |
| `--region` | `us-east-1` | AWS region for AAM API calls. |

### Trust policy

| Flag | Default | Description |
|------|---------|-------------|
| `--trust-policy <file>` | — | Path to a JSON file containing a custom trust policy **statement** to merge into each role's trust policy, instead of the built-in default. Confused-deputy conditions (`aws:SourceAccount`, `aws:SourceArn`) are still injected on top. |
| `--no-tag-session` | off | Remove the `sts:TagSession` action from the trust statement before applying. |

By default, the tool merges this statement into each role's trust policy:

```json
{
  "Sid": "AAMTrustPolicyStatement",
  "Effect": "Allow",
  "Principal": { "Service": "account-access.amazonaws.com" },
  "Action": ["sts:AssumeRole", "sts:SetContext", "sts:TagSession"]
}
```

- **`sts:TagSession` is included by default.** It allows AAM to pass session tags when assuming the role. Use `--no-tag-session` to omit it if you do not need or want roles to leverage session tags.
- **`--trust-policy`** accepts either a bare statement object or a full policy document (in which case the first statement is used). The action list you supply is honored as-is, except that `--no-tag-session` will still strip `sts:TagSession` if present.

### Other

| Flag | Description |
|------|-------------|
| `--rollback <file>` | Restore trust policies from a backup JSON file. For multi-account backups, combine with `--profiles` or `--account-ids` + `--role-name` to resolve credentials per account (the account ID is read from each role ARN in the backup). |

---

## Entitlement Input Formats

### Columnar CSV (recommended)

The `--entitlement-csv` flag accepts a CSV with explicit columns:

```csv
Group/Principal,Principal Type,Account ID,Role Name,Role ARN
admins,GROUP,111111111111,PowerUser,arn:aws:iam::111111111111:role/PowerUser
jane@example.com,USER,222222222222,ReadOnly,arn:aws:iam::222222222222:role/ReadOnly
```

**Column order does not matter** — headers are matched by name, not position.

| Column | Required | Description |
|--------|----------|-------------|
| Group/Principal | Yes | The IdC group display name or user name to create the entitlement for. |
| Principal Type | No | `GROUP` or `USER`. Defaults to `GROUP` if omitted. |
| Account ID | Yes | 12-digit AWS account ID where the role exists. |
| Role Name | Yes | IAM role name (used to construct ARN if Role ARN is omitted). |
| Role ARN | No | Full role ARN. Constructed from Account ID + Role Name if omitted. |

This format is identical to what the UI exports from the entitlement mapping table.

---

## IAM Permissions

```
# Discovery (read-only)
iam:ListSAMLProviders
iam:ListRoles
iam:GetRole
iam:ListAttachedRolePolicies
iam:ListRolePolicies
sts:GetCallerIdentity

# Migration (write)
iam:UpdateAssumeRolePolicy

# Multi-account
sts:AssumeRole

# Entitlement creation
account-access:CreateEntitlement
account-access:GetApplication
```

---

## Safety

- **Backup before modify** — trust policies are backed up to a timestamped JSON before any update (both interactive and `--apply-only` modes).
- **Rollback available** — `--rollback <backup_file>` restores original trust policies.
- **Idempotent** — roles already containing the AAM service principal (`account-access.amazonaws.com`) are skipped.
- **Fail-and-continue** — a failure on one role doesn't abort others.
- **GA endpoint** — AAM calls use the GA endpoint (`account-access.<region>.api.aws`).
- **ValidationException retry** — entitlement creation retries up to 3 times with backoff for IAM propagation delay.
- **Multi-IDP** — supports selecting multiple identity providers (comma-separated numbers) and scanning all roles in a single pass.

---

## Architecture

```
AAM_role_evaluation.py    ← CLI entry point (prompts, CSV, orchestration)
        │
        └── imports ──→  lib.py  ← shared library (stateless functions)
                              │
                              └── also imported by ui/backend/iam_federation.py (UI adapter)
```

The `lib.py` module is the single source of truth for discovery, migration, and entitlement creation logic. Both the CLI and the UI import from it.

---

## CSV Output Format

### Single-account mode

| Column | Description |
|--------|-------------|
| Role Name | IAM role name |
| Policy Name | Attached or inline policy name |
| Policy Type | `AWS Managed`, `Customer Managed`, or `Inline` |
| Permission Boundary | ARN of the permission boundary attached to the role (empty if none) |
| Trust Policy Name | Summary of the current trust relationship |

### Multi-account mode

The consolidated CSV (`AAM_role_evaluation_multi.csv`) adds two extra leading columns:

| Column | Description |
|--------|-------------|
| Account ID | 12-digit AWS account ID the role belongs to |
| Role Name | IAM role name |
| Role ARN | Full role ARN |
| Policy Name | Attached or inline policy name |
| Policy Type | `AWS Managed`, `Customer Managed`, or `Inline` |
| Permission Boundary | ARN of the permission boundary attached to the role (empty if none) |
| Trust Policy Name | Summary of the current trust relationship |

---

## Rollback

Before any trust policy modification, the tool writes a timestamped JSON backup
keyed by each role's **full ARN** (which embeds the account ID). Rollback restores
the exact trust policy documents that were in place before the update.

### Single account

```bash
python AAM_role_evaluation.py --rollback AAM_trust_backup_<account>_<timestamp>.json
```

With no credential flags, the rollback uses your default session (current account).
This also handles legacy backups that used plain role-name keys.

### Multi-account

Because backup keys are full role ARNs, the tool extracts the account ID from each
role and routes its restore to the matching account. Provide credentials the same
way you did for the migration — with `--profiles` or `--account-ids` + `--role-name`:

```bash
# Rollback across accounts using named profiles
python AAM_role_evaluation.py \
  --rollback AAM_trust_backup_apply_only_<timestamp>.json \
  --profiles prod-account,dev-account,staging-account

# Rollback across accounts by assuming a role into each target
python AAM_role_evaluation.py \
  --rollback AAM_trust_backup_apply_only_<timestamp>.json \
  --account-ids 111111111111,222222222222 \
  --role-name OrganizationAccountAccessRole
```

Notes:

- The tool prints which accounts appear in the backup and **warns** if you did not
  supply credentials for one of them — roles in an unresolved account are **skipped**,
  not failed.
- Rollback is **fail-and-continue**: a failure on one role doesn't abort the rest.
  The summary reports succeeded / skipped / failed counts.
