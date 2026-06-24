

### Part 2: IAM Federation → AAM 

For customers using SAML-based IAM federation who want to consolidate into AAM's entitlement model.



## Problem

Organizations using IAM SAML-based direct federation (e.g., Microsoft Entra ID, Okta, OneLogin) to grant access to AWS accounts accumulate IAM roles with trust policies tied to their external identity provider. When migrating to AWS IAM Identity Center or AWS Account Access Manager (AAM), these roles need their trust policies updated to reference the new service principal instead of (or in addition to) the IAM SAML provider.

Doing this manually across dozens or hundreds of roles is error-prone and difficult to audit. Teams also need a way to codify the new role definitions into their CI/CD pipelines using Infrastructure as Code.

## Solution

This toolset provides:

1. **Discovery and reporting** — Scan an AWS account, identify all SAML-federated roles for a given identity provider, and produce a CSV inventory.
2. **Trust policy migration** — Optionally update those roles' trust policies in-place (with backup and rollback support).
3. **IaC template generation** — Produce CloudFormation and Terraform templates from the CSV so customers can manage the migrated roles through their existing deployment pipelines.

---

## Prerequisites

- Python 3.8+
- AWS credentials configured (`aws configure`, environment variables, or instance profile) or use 'aws login' at command prompt
- IAM permissions: `iam:ListSAMLProviders`, `iam:ListRoles`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRole`, `iam:UpdateAssumeRolePolicy`

Install dependencies:

```bash
pip install boto3
```

---

## Scripts

### `AAM_role_evaluation.py`

The primary evaluation and migration script.

**Usage:**

```bash
# Evaluate roles and optionally update trust policies
python3 AAM_role_evaluation.py

# Rollback trust policies from a backup
python3 AAM_role_evaluation.py --rollback <backup_file>
```

**What it does:**

1. Lists SAML identity providers in the account
2. Prompts you to select the provider to evaluate against
3. Scans all IAM roles and filters those with a trust policy referencing the selected provider
4. Generates a CSV report (`AAM_role_evaluation_<account_id>.csv`)
5. Offers to update trust policies with the new AAM service principal

**Trust policy update options:**

| Option | Behavior |
|--------|----------|
| ADD | Keeps the existing SAML trust statement, appends the new AAM statement |
| REPLACE | Removes the SAML trust statement, adds the new AAM statement |
| SKIP | Makes no changes |

Before any modification, the script creates a timestamped JSON backup of the original trust policies.

---

### `generate_iac_templates.py`

Generates CloudFormation and Terraform templates from the CSV report.

**Usage:**

```bash
python3 generate_iac_templates.py AAM_role_evaluation_<account_id>.csv
```

**Outputs:**

| File | Description |
|------|-------------|
| `aam_roles_cloudformation.yaml` | AWS CloudFormation template defining all roles with the new trust policy |
| `aam_roles_terraform.tf` | Terraform configuration with shared trust policy data source |

---

## CSV Output Format

The evaluation script produces a CSV with the following columns:

| Column | Description |
|--------|-------------|
| Role Name | IAM role name |
| Policy Name | Attached or inline policy name (`(none)` if the role has no policies) |
| Policy Type | `AWS Managed`, `Customer Managed`, or `Inline` |
| Trust Policy Name | Human-readable summary of the current trust relationship |

---

## Deploying the Generated Templates

### CloudFormation

```bash
aws cloudformation deploy \
  --template-file aam_roles_cloudformation.yaml \
  --stack-name aam-migrated-roles \
  --capabilities CAPABILITY_NAMED_IAM
```

To override the trust principal:

```bash
aws cloudformation deploy \
  --template-file aam_roles_cloudformation.yaml \
  --stack-name aam-migrated-roles \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides TrustServicePrincipal=your-service-principal.amazonaws.com
```

### Terraform

```bash
terraform init
terraform plan
terraform apply
```

To override the trust principal:

```bash
terraform apply -var="trust_service_principal=your-service-principal.amazonaws.com"
```

---

## Rollback

If you used the evaluation script to update trust policies directly and need to revert:

```bash
python3 AAM_role_evaluation.py --rollback AAM_trust_backup_<account_id>_<timestamp>.json
```

This restores the exact trust policy documents that were in place before the update.

---

## Important Notes

- **Inline policies**: The CSV captures inline policy names but not their full documents. Generated IaC templates include `TODO` placeholders for inline policies that must be filled in before deployment.
- **Existing roles**: The generated templates create new roles. If the roles already exist in the account, you'll need to either import them into your IaC state or delete them first.
- **Testing**: Deploy to a non-production account first to validate the templates before rolling out to production.

---

## File Structure

```
.
├── README.md
├── AAM_role_evaluation.py              # Discovery, reporting, and trust policy migration
├── generate_iac_templates.py           # IaC template generator
├── AAM_role_evaluation_<account>.csv   # Generated CSV report
├── aam_roles_cloudformation.yaml       # Generated CloudFormation template
├── aam_roles_terraform.tf              # Generated Terraform template
└── AAM_trust_backup_<account>_<ts>.json # Trust policy backup (created during updates)
```

