# Resource Policy Scanner

Scans resource-based policies across AWS services for one or more search strings. Useful for finding references to specific principals, account IDs, or ARN patterns buried in resource policies across your environment.

## How it works

The scanner iterates through 35+ AWS services, retrieves every resource-based policy it can find, and checks each one for your search terms. It supports:

- Single-account or multi-account (hub-and-spoke role assumption)
- All commercial regions or a specified subset
- Service filtering (include or exclude)
- IAM-style wildcards (`*` and `?`) in search terms
- Parallel API calls for faster scanning
- Organization SCPs and RCPs (when running from a management or delegated admin account)

Results are written to a JSON file with the matched resource ARN, service, account, and the full policy document.

## Prerequisites

- Python 3.10+
- boto3 / botocore
- AWS credentials with read-only IAM permissions across the services you want to scan

The minimum IAM permissions needed vary by service but generally include `Get*Policy`, `List*`, and `Describe*` actions. A managed policy like `ReadOnlyAccess` covers most cases.

## Installation

```bash
cd "Utilites/resource_policy_scan"
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

### Python version (recommended)

```bash
# Single account — uses your current credentials
python3 scan_resource_policies.py --search "123456789012,arn:aws:iam::123456789012:root"

# Multi-account — assumes a role in each target account
python3 scan_resource_policies.py \
    --account-ids 111111111111,222222222222 \
    --role-name ReadOnlyRole \
    --search "old-idp.example.com" \
    --regions us-east-1,us-west-2

# Include Organization SCPs and RCPs (requires management account credentials)
python3 scan_resource_policies.py \
    --search "arn:aws:iam::*:root" \
    --management-account

# Scan only specific services
python3 scan_resource_policies.py \
    --search "s3.amazonaws.com" \
    --services "Lambda,SNS,SQS"

# Exclude slow or irrelevant services
python3 scan_resource_policies.py \
    --search "some-principal" \
    --exclude-services "Rekognition,Lex V2"

# List all available service names
python3 scan_resource_policies.py --list-services
```

### Shell version

A simpler bash implementation was previously provided but has been removed. Use the Python version for all workflows.

## CLI options (Python)

| Option | Description |
|--------|-------------|
| `--search` | Comma-separated search strings (required). Supports `*` and `?` wildcards. |
| `--account-ids` | Comma-separated AWS account IDs to scan. Requires `--role-name`. |
| `--role-name` | IAM role name to assume in each target account. |
| `--management-account` | Also scan Organization SCPs and RCPs. |
| `--regions` | Comma-separated regions. Defaults to all enabled regions. |
| `--services` | Comma-separated services to include. Defaults to all. |
| `--exclude-services` | Comma-separated services to skip. |
| `--workers` | Max parallel threads per service (default: 5). |
| `--output` | Output JSON file path (default: `scan_results.json`). |
| `--list-services` | Print available service names and exit. |

## Services scanned

### Global (non-regional)

- S3 (bucket policies)
- Organizations (SCPs + RCPs)
- IAM (role trust policies)
- AWS Private CA
- Serverless Application Repository

### Regional (per-region)

API Gateway, Backup Vaults, CloudTrail, CloudWatch Logs, CodeArtifact, CodeBuild, DynamoDB, Entity Resolution, EventBridge, EventBridge Schemas, Glue, KMS, Kinesis Data Streams, Lambda (functions + layer versions), Lex V2, OpenSearch, OpenSearch Serverless, S3 Express (Directory Buckets), S3 Tables, Secrets Manager, SES v2, SNS, SQS, ECR, EFS, Redshift Serverless, Rekognition, VPC Endpoints, MSK, Signer, VPC Lattice, Network Firewall

## Output format

```json
{
  "search_terms": ["123456789012"],
  "regions_scanned": ["us-east-1", "us-west-2"],
  "total_matches": 3,
  "matches": [
    {
      "resource_arn": "arn:aws:s3:::my-bucket",
      "service": "S3",
      "matched_terms": ["123456789012"],
      "policy": { "Version": "2012-10-17", "Statement": [...] },
      "account_id": "111111111111"
    }
  ],
  "skipped_resources": [
    {
      "resource_arn": "arn:aws:kms:us-east-1:XXXXXXXXXXXX:key/abc-123",
      "service": "KMS",
      "error": "AccessDeniedException",
      "account_id": "111111111111"
    }
  ],
  "total_skipped": 1
}
```

| Field | Description |
|-------|-------------|
| `search_terms` | The search strings that were scanned for. |
| `regions_scanned` | Regions included in the scan. |
| `total_matches` | Number of resources with at least one matching term. |
| `matches` | Array of matched resources with their full policy document. |
| `skipped_resources` | Array of resources that could not be scanned (access denied, throttled, etc.). |
| `total_skipped` | Count of skipped resources. |

## Performance notes

- Each service scanner runs sequentially, but API calls within a service are parallelized (controlled by `--workers`).
- Scanning all services across all regions in a single account typically takes 3-10 minutes depending on resource count and API throttling.
- Use `--services` or `--exclude-services` to reduce scan time when you know which services are relevant.
- The scanner gracefully handles throttling and access-denied errors — missing permissions for a service are silently skipped.
