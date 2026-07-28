# IAM Federation → AAM — CLI Tool

Evaluate and migrate SAML-federated IAM roles to AWS Account Access Manager (AAM). This tool discovers roles that trust your SAML identity provider, updates their trust policies to enable AAM, and creates AAM entitlements to preserve who-can-access-what.

This is the standalone CLI. For the browser-based console (recommended for most users), see the [main README](../README.md).

---

## Quick Start

```bash
cd "IAM Federation to AAM"
pip install boto3

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

# With entitlement creation after discovery (columnar CSV)
python AAM_role_evaluation.py \
  --aam-application-arn "arn:aws:account-access:us-east-1:123456:application/app-id" \
  --entitlement-csv entitlement_mappings.csv \
  --region us-east-1
```

---

## What It Does

1. **Lists SAML identity providers** in the account
2. **Prompts you to select** which provider to evaluate against
3. **Scans all IAM roles** (parallelized) and filters to those with a trust policy referencing the selected provider
4. **Generates a CSV report** with role names, attached policies, and trust policy details
5. **Offers to update trust policies** — ADD (keep SAML, add AAM) or REPLACE (remove SAML, add AAM only)
6. **Creates AAM entitlements** (optional) from a group-to-role mapping

---

## What It Changes

| Phase | Changes? | What happens |
|-------|----------|-------------|
| Discovery + CSV | No | Read-only. Lists providers and roles. |
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

### Entitlement creation

| Flag | Default | Description |
|------|---------|-------------|
| `--aam-application-arn` | — | AAM application ARN. Required for entitlement creation. |
| `--entitlement-csv` | — | Columnar CSV with Group, Account, Role columns. Direct mapping. |
| `--group-names-file` | — | File with IdP group names (one per line). Used with `--group-pattern`. |
| `--group-pattern` | `{principal}_{account}_{role}` | Pattern to parse group names into entitlement mappings. |
| `--region` | `us-east-1` | AWS region for AAM API calls. |

### Other

| Flag | Description |
|------|-------------|
| `--rollback <file>` | Restore trust policies from a backup JSON file. |

---

## Entitlement Input Formats

### Columnar CSV (recommended)

The `--entitlement-csv` flag accepts a CSV with explicit columns:

```csv
Group/Principal,Account ID,Role Name,Role ARN
admins,111111111111,PowerUser,arn:aws:iam::111111111111:role/PowerUser
devs,222222222222,ReadOnly,arn:aws:iam::222222222222:role/ReadOnly
```

The "Role ARN" column is optional — if omitted, it's constructed from Account ID + Role Name.

### Pattern-based (legacy)

The `--group-names-file` + `--group-pattern` approach parses group names using a pattern:

```bash
python AAM_role_evaluation.py \
  --aam-application-arn "arn:..." \
  --group-names-file groups.txt \
  --group-pattern "{principal}_{account}_{role}"
```

Where `groups.txt` contains:
```
admins_111111111111_PowerUser
devs_222222222222_ReadOnly
```

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
- **Idempotent** — roles already containing the AAM service principal (`account-access.amazonaws.com` or `account-access-preview.amazonaws.com`) are skipped.
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

| Column | Description |
|--------|-------------|
| Role Name | IAM role name |
| Policy Name | Attached or inline policy name |
| Policy Type | `AWS Managed`, `Customer Managed`, or `Inline` |
| Trust Policy Name | Summary of the current trust relationship |

---

## Rollback

```bash
python AAM_role_evaluation.py --rollback AAM_trust_backup_<account>_<timestamp>.json
```

Restores the exact trust policy documents that were in place before the update.
