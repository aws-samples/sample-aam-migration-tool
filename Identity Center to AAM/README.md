# IdC-to-AAM Migration Tool

A Python 3 command-line tool that migrates AWS **IAM Identity Center (IdC)**
configuration to **Account Access Manager (AAM)**. It inventories your existing
permission sets and account assignments, produces an editable Excel migration
plan, recreates each permission set as an IAM role (or emits the equivalent
Infrastructure-as-Code), and creates the AAM entitlements that preserve who can
access what — all with an audit trail and a final mapping report.

This is the standalone CLI. For the browser-based console (recommended for most users), see the [main README](../README.md).

The tool runs in clear, sequential phases:

```
inventory  →  migration plan  →  role creation  →  entitlements  →  mapping report
(read-only)   (editable XLSX)    (apply | iac)      (AAM)            (XLSX/CSV/JSON)
```

In `apply` mode the tool asks for an explicit confirmation before it changes
anything; `generate-iac` (the default) writes a CloudFormation template and
changes nothing in AWS.





get all assignments and permission set details
- generate a csv/excel that contains all this information
- excel should contain group/user, permission set name, default role name we want to create, trust policy for default role, policies attached to permission set

then generates cloudformation/terraform with the default roles (including the trust policy and policies required)
- user is given option to modify role name either for each role or all of the roles (either can re-define the default role path or the full name of the role)

- there should be an option to run this in a single account or the entire org, the default should be a single account. We should have a disclaimer for the org run that they may get throttled

It is one of three components in the larger Truffle migration toolkit.

---

## Table of contents

- [Concepts](#concepts)
- [Requirements](#requirements)
- [Installation](#installation)
- [Credentials and region](#credentials-and-region)
- [Quick start](#quick-start)
- [How it works (phases)](#how-it-works-phases)
- [Command reference (every flag)](#command-reference-every-flag)
- [Common workflows](#common-workflows)
- [Outputs](#outputs)
- [IAM permissions needed](#iam-permissions-needed)
- [Safety model](#safety-model)
- [For contributors: running the tests](#for-contributors-running-the-tests)
- [Limitations / out of scope](#limitations--out-of-scope)

---

## Concepts

| Term | Meaning |
|------|---------|
| **Hub account** | The account you run from — holds the IdC instance and AAM. Resolved automatically via STS. |
| **Spoke / target account** | An account the tool reaches into (multi-account mode) by assuming a role. |
| **Migration plan** | An editable XLSX mapping each permission set to a target IAM role name (1:1). The source of truth for role names. |
| **Apply mode** | Creates IAM roles live via the IAM API. |
| **Generate-iac mode** (default) | Emits a CloudFormation template (roles + AAM entitlements) and mutates nothing. |
| **AAM application** | An operator-managed prerequisite. You create it beforehand and pass its ARN; the tool never creates it. |

---

## Requirements

- Python 3.11+
- The custom **boto3 / botocore 1.43.55** wheels that expose the
  `accountaccess` (AAM) client. AAM is not yet in public boto3, so these are
  required for the entitlement phase (This will get removed once boto3 is updated).
- AWS credentials for the account that holds your IdC instance.

---

## Installation

```bash
cd "Identity Center to AAM"
python3 -m venv .venv
source .venv/bin/activate

# Install the custom AAM-aware SDK wheels FIRST (again to be removed when boto3 is released):
pip install /path/to/botocore-1.43.55-py3-none-any.whl
pip install /path/to/boto3-1.43.55-py3-none-any.whl

# Then the rest of the dependencies:
pip install -r requirements.txt
```

Verify the AAM client is available:

```bash
python -c "import boto3; boto3.client('accountaccess', region_name='us-east-1'); print('AAM client OK')"
```

---

## Credentials and region

The tool uses standard boto3 credential resolution (environment variables,
named profiles, or SSO). Select a profile per session:

```bash
export AWS_PROFILE=your-idc-admin-profile
export AWS_REGION=us-east-1
```

> **Region matters.** IdC `ListPermissionSets` only works in the **primary
> region** of your Identity Center instance. Point the tool at that region with
> `--region` (default `us-east-1`).

Confirm you are who you expect:

```bash
python -c "import boto3; print(boto3.client('sts').get_caller_identity())"
```

---

## Quick start

The recommended path is generate-iac first (which changes nothing in AWS), review the template, then optionally apply.

```bash
# 1. Read your IdC, write the migration plan, and emit CloudFormation.
#    This makes NO changes to your AWS environment.
python idc_to_aam.py --region us-east-1 --account-scope single \
  --trust-policy trust.json --plan-output my_plan.xlsx

# 2. Re-run with your edited plan + AAM application ARN to include entitlements.
#    Still no live IAM/AAM change — it only writes the template.
python idc_to_aam.py \
  --region us-east-1 \
  --account-scope single \
  --role-creation-mode generate-iac \
  --plan my_plan.xlsx \
  --trust-policy trust.json \
  --aam-application-arn "arn:aws:account-access:us-east-1:<acct>:application/<id>" \
  --iac-output-dir output
```

---

## How it works (phases)

1. **Inventory (always runs, read-only).** Discovers the IdC instance, lists
   permission sets and their policies/boundaries/CMP references, lists account
   assignments, resolves user/group display names, and writes
   `inventory_<run_id>.json`.
2. **Migration plan.** Generates an editable XLSX (one row per permission set,
   default `RoleName = AAM-<PermissionSetName>`) or consumes an edited one via
   `--plan`.
3. **Confirmation (apply mode only).** In `apply` mode the tool prints an
   explicit "this will change your environment" prompt before any change.
   In `generate-iac` mode there is no prompt — it writes files and changes nothing.
4. **Role creation.** `apply` creates IAM roles live; `generate-iac` (default)
   writes `output/<run_id>/roles.yaml`.
5. **Entitlements.** Against your supplied AAM application, creates one
   entitlement per assignment (apply mode) or emits them as
   `AWS::AccountAccess::Entitlement` resources (generate-iac mode).
6. **Mapping report.** Writes `mapping_<run_id>.xlsx` (or CSV/JSON): one row per
   assignment with the full principal → permission set → account → role → entitlement chain.

---

## Command reference (every flag)

Run `python idc_to_aam.py --help` for the live list.

### Account targeting
| Flag | Default | Description |
|------|---------|-------------|
| `--account-scope {single,multi,org}` | `single` | `single`: operate only in the hub account with current credentials. `multi`: assume a role into each specified target account. `org`: scan all accounts provisioned in the IdC instance (may be throttled in large orgs). |
| `--account-ids` | — | Comma-separated AWS account IDs. Defines which accounts to discover permission sets/assignments for AND where to create roles. **Required for `multi`.** |
| `--role-name` | — | Name of the IAM role to assume in each target account. **Required for `multi` with assume-role.** |
| `--profiles` | — | Comma-separated AWS profile names for multi-account. Each resolved to its account via GetCallerIdentity. Alternative to `--account-ids` + `--role-name`. |

### Mode
| Flag | Default | Description |
|------|---------|-------------|
| `--auto-approve` | off | Skip the confirmation prompt in apply mode. |
| `--role-creation-mode {apply,generate-iac}` | `generate-iac` | `generate-iac` (default) reads your environment and writes a CloudFormation template, changing nothing in AWS; `apply` creates roles and entitlements live. |

### Role creation
| Flag | Default | Description |
|------|---------|-------------|
| `--trust-policy` | — | Path to the JSON trust policy used as each role's AssumeRolePolicyDocument. Required (it defines the roles in both modes). A ready-made AAM trust policy ships as `trust.json`. |
| `--role-path` | `/aam/` | IAM path applied to every created/emitted role. |
| `--tag KEY=VALUE` | — | Tag applied to every role. Repeatable. |
| `--permission-boundary` | — | ARN of a permission boundary to attach to every role. |
| `--convert-inline-to-cmp` | off | Convert each permission set's inline policy into a customer managed policy before attaching. |
| `--cmp-name-template` | `AAM-{permission_set_name}-inline` | Name template for converted CMPs. |
| `--role-name-template` | `AAM-{permission_set_name}` | Default role-name generator used when first producing the migration plan. |

### Migration plan
| Flag | Default | Description |
|------|---------|-------------|
| `--plan` | — | Path to an edited migration plan XLSX to consume. When omitted, defaults are generated from the inventory. |
| `--plan-output` | `migration_plan_<run_id>.xlsx` | Where to write the generated plan. |

### AAM
| Flag | Default | Description |
|------|---------|-------------|
| `--aam-application-arn` | — | ARN of your pre-existing AAM application. Required in apply mode; in generate-iac mode it is optional (when supplied, entitlement resources are added to the template). |
| `--validate-aam-application` | off | Verify the application exists via `GetApplication` before use. |
| `--aam-idc-instance-arn` | auto | Override the IdC instance ARN (auto-discovered by default). |

### IaC
| Flag | Default | Description |
|------|---------|-------------|
| `--iac-output-dir` | `output` | Base dir for generated IaC. Template is written to `<dir>/<run_id>/roles.yaml`. |

### Audit & output
| Flag | Default | Description |
|------|---------|-------------|
| `--audit-to-cloudwatch` | off | Emit audit entries to CloudWatch Logs (requires `--cloudwatch-log-group`). |
| `--cloudwatch-log-group` | — | CloudWatch log group name. |
| `--audit-to-file` | off | Append audit entries to a CSV (requires `--audit-file-path`). |
| `--audit-file-path` | — | Path for the audit CSV. |
| `--inventory-output` | `inventory_<run_id>.json` | Path for the inventory JSON. |
| `--mapping-format {XLSX,CSV,JSON}` | `XLSX` | Mapping report format. |
| `--mapping-output` | `mapping_<run_id>.<ext>` | Path for the mapping report. |

### Other
| Flag | Default | Description |
|------|---------|-------------|
| `--workers` | `5` | Max concurrent worker threads. |
| `--region` | `us-east-1` / `AWS_DEFAULT_REGION` | AWS region (use your IdC primary region). |

If no audit sink is selected, audit entries print to stdout as JSON.

---

## Common workflows

**Preview only (reads your environment, writes the template, no AWS changes):**
```bash
python idc_to_aam.py --region us-east-1 --trust-policy trust.json
```

**Generate CloudFormation for review/deploy (default mode):**
```bash
python idc_to_aam.py --region us-east-1 \
  --plan my_plan.xlsx --trust-policy trust.json \
  --aam-application-arn arn:aws:account-access:us-east-1:<acct>:application/<id>
```

**Create roles and entitlements live (apply mode):**
```bash
python idc_to_aam.py --region us-east-1 \
  --role-creation-mode apply \
  --plan my_plan.xlsx --trust-policy trust.json \
  --aam-application-arn arn:aws:account-access:us-east-1:<acct>:application/<id>
```

**Unattended run (CI):** add `--auto-approve`.

---

## Outputs

| File | When | Contents |
|------|------|----------|
| `inventory_<run_id>.json` | always | Full IdC inventory snapshot. |
| `migration_plan_<run_id>.xlsx` | plan generation | Editable permission-set → RoleName plan. |
| `output/<run_id>/roles.yaml` | generate-iac | CloudFormation: `AWS::IAM::Role` + `AWS::AccountAccess::Entitlement`. |
| `mapping_<run_id>.{xlsx,csv,json}` | end of run | One row per assignment: principal → permission set → account → role → entitlement → status. |

---

## IAM permissions needed

Inventory (read-only): `sso:ListInstances`, `sso:ListPermissionSets`,
`sso:DescribePermissionSet`, `sso:GetInlinePolicyForPermissionSet`,
`sso:ListManagedPoliciesInPermissionSet`,
`sso:ListCustomerManagedPolicyReferencesInPermissionSet`,
`sso:GetPermissionsBoundaryForPermissionSet`,
`sso:ListAccountsForProvisionedPermissionSet`, `sso:ListAccountAssignments`,
`identitystore:DescribeUser`, `identitystore:DescribeGroup`,
`sts:GetCallerIdentity`.

Apply mode adds: `iam:CreateRole`, `iam:GetRole`, `iam:AttachRolePolicy`,
`iam:PutRolePolicy`, `iam:CreatePolicy`, `iam:GetPolicy`,
`iam:PutRolePermissionsBoundary`, `iam:TagRole`, and (multi-account)
`sts:AssumeRole` into each target.

Entitlements add the AAM `account-access` actions: `GetApplication` (validation)
and `CreateEntitlement` / `ListEntitlements`.

---

## Safety model

- **generate-iac mode (the default)** only reads AWS and writes local files; it
  makes no change to your environment.
- In **apply mode**, an explicit "this will change your environment"
  confirmation must pass before anything is created (skip it with
  `--auto-approve`).
- **Idempotent:** existing roles and entitlements are detected and reused, not
  duplicated.
- **Fail-and-continue:** a failure on one permission set, account, or policy is
  logged and skipped; the run continues.
- The tool **never** creates or modifies the AAM application, and never calls
  `CreateApplication`.

---

## For contributors: running the tests

> You do **not** need this to use the tool — it's only for developers changing
> the code. The tests never touch AWS.

```bash
.venv/bin/python -m pytest -q
```

The suite is unit + property-based (Hypothesis). It runs entirely offline: AWS
is mocked with `moto` and the preview AAM client is replaced with an injected
stub, so no credentials and no real API calls are involved.

---

## Limitations / out of scope

- **Terraform output** is not yet emitted (no AAM Terraform provider yet);
  CloudFormation only. Tracked in `TODO_AAM_IAC.md`.
- **The AAM application** is an operator-managed prerequisite and is not emitted
  as IaC.
- **Multi-account IaC distribution** (CloudFormation StackSets) is future work;
  generated templates target a single account.
- The tool does **not** modify resource-based policies, migrate IAM Federation,
  or analyze SCPs/RCPs/VPC endpoint policies (other Truffle components cover those).


---

## Architecture

```
idc_to_aam.py          ← CLI entry point (orchestration, prompts, phases)
├── inventory.py       ← IdC discovery (permission sets, assignments)
├── role_creator.py    ← IAM role creation (apply mode)
├── entitlement_creator.py  ← AAM entitlement creation
├── iac_generator.py   ← CloudFormation template generation (per-account)
├── plan.py            ← Migration plan (XLSX read/write)
├── mapping_reporter.py ← Final mapping report
└── lib.py             ← Shared library (stateless functions, also used by UI adapter)
```

The `lib.py` module provides stateless functions for IdC discovery, role creation,
and entitlement creation. The UI adapter (`ui/backend/idc.py`) imports these directly,
ensuring a single source of truth for core logic across both CLI and UI.
