# Truffle — Managed Backend Architecture (Local UI + AWS Backend)

This document describes the architecture for running the Truffle AAM Migration
Console as a **local UI** backed by a **managed serverless API** on AWS. The
frontend runs on the user's machine; long-running scan and migration jobs are
submitted to a private AWS backend that handles orchestration, parallelism, and
cross-account access.

---

## Design Goals

| Goal | Approach |
|------|----------|
| No public-facing resources | Regional API Gateway with IAM (SigV4) auth — no Cognito, no CloudFront |
| Minimal client-side change | Existing Flask UI stays; a config toggle switches between local execution and managed backend |
| Scalable multi-account scanning | Step Functions fan out across accounts/regions; Lambda parallelizes within a single account+region |
| Simple cross-account access | StackSet-deployed IAM role in every target account |
| Cost-effective | Pay-per-request serverless — no idle cost |
| Resilient to long-running jobs | Step Functions Standard Workflows (up to 1-year execution) with built-in retry |

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  User's Machine                                                              │
│                                                                              │
│  ┌────────────────────┐       ┌──────────────────────────────────────────┐   │
│  │  React/Cloudscape  │ HTTP  │  Flask Backend (localhost)                │   │
│  │  UI (localhost:5173)│──────▶│                                          │   │
│  └────────────────────┘       │  TRUFFLE_MODE=managed                    │   │
│                               │  ┌────────────────────────────────────┐  │   │
│                               │  │  SigV4 Signing Proxy               │  │   │
│                               │  │  (uses local AWS creds to sign)    │  │   │
│                               │  └──────────────┬─────────────────────┘  │   │
│                               └─────────────────┼────────────────────────┘   │
└─────────────────────────────────────────────────┼────────────────────────────┘
                                                  │ HTTPS (SigV4-signed)
                                                  ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  AWS Account (Truffle Backend)                                               │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐    │
│  │  API Gateway (Regional, IAM Auth on ALL routes)                      │    │
│  │  Resource Policy: Deny all except aws:PrincipalOrgID = o-xxxxxxxx    │    │
│  └───────────────────────────────┬──────────────────────────────────────┘    │
│                                  │                                           │
│           ┌──────────────────────┼──────────────────────┐                    │
│           ▼                      ▼                      ▼                    │
│    ┌────────────┐      ┌──────────────────┐    ┌──────────────────┐          │
│    │ Lambda     │      │ Lambda           │    │ Lambda           │          │
│    │ (StartJob) │      │ (GetStatus)      │    │ (GetResult)      │          │
│    └─────┬──────┘      └────────┬─────────┘    └────────┬─────────┘          │
│          │                      │                       │                    │
│          ▼                      ▼                       ▼                    │
│  ┌───────────────┐      ┌─────────────┐         ┌─────────────┐             │
│  │Step Functions │      │  DynamoDB   │         │  S3 Results │             │
│  │(Standard)     │      │  (Jobs)     │         │  Bucket     │             │
│  └───────┬───────┘      └─────────────┘         └─────────────┘             │
│          │                                                                   │
│          │  Map (accounts) → Map (regions)                                   │
│          ▼                                                                   │
│  ┌───────────────────────────────────────────────────┐                       │
│  │  Lambda (ScanUnit)                                │                       │
│  │  - Assumes role in target account                 │                       │
│  │  - Parallelizes API calls within the unit         │                       │
│  │    (asyncio + semaphore for throttle control)     │                       │
│  └───────────────────────────────────────────────────┘                       │
│          │                                                                   │
│          │ sts:AssumeRole                                                    │
│          ▼                                                                   │
│  ┌───────────────────────────────────────────────────┐                       │
│  │  Target Accounts (StackSet-deployed role)         │                       │
│  │  TruffleRole — read + iam:UpdateAssumeRolePolicy  │                       │
│  └───────────────────────────────────────────────────┘                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Client-Side: Execution Mode Toggle

The existing Flask backend gains a single config switch:

```python
# config.py
EXECUTION_MODE = os.environ.get("TRUFFLE_MODE", "local")   # "local" | "managed"
API_ENDPOINT   = os.environ.get("TRUFFLE_API_ENDPOINT", "") # e.g. https://<id>.execute-api.<region>.amazonaws.com/prod
AWS_REGION     = os.environ.get("TRUFFLE_API_REGION", "us-east-1")
```

### Impact on Existing Code

| Component | Local mode (unchanged) | Managed mode (new) |
|-----------|----------------------|-------------------|
| React UI | Calls `/api/*` on localhost | Same — no change |
| Flask routes (`app.py`) | Unchanged | Unchanged |
| `jobs.py` | Spawns threads, runs scanner in-process | Forwards to managed API via SigV4 |
| `policy_analysis.py` | Used directly | Not used (logic lives in Lambda) |
| `checkpoint.py` | Active (resume interrupted scans) | Not needed (Step Functions retries) |
| Scanner module | Loaded and executed locally | Not used client-side |

The `jobs.py` module becomes a dispatcher:

```python
# jobs.py
from . import config

if config.EXECUTION_MODE == "managed":
    from ._jobs_managed import start_scan, get, start_iam_discover, ...
else:
    from ._jobs_local import start_scan, get, start_iam_discover, ...
```

- `_jobs_local.py` — the current thread-based implementation (renamed from `jobs.py`)
- `_jobs_managed.py` — thin SigV4 signing client (~100 lines) that POSTs to the managed API and GETs status

---

## API Gateway: Regional + IAM Auth

### Configuration

- **Type:** Regional (not Edge-optimized, not Private)
- **Authorization:** IAM (`AWS_IAM`) on every route — no exceptions
- **Protocol:** HTTPS only (default for API Gateway)

### Resource Policy

Locks the API to callers within the AWS Organization:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/prod/*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-yourorgid"
        }
      }
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-east-1:ACCOUNT_ID:API_ID/prod/*",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-yourorgid"
        }
      }
    }
  ]
}
```

This means:
- Unsigned requests → 403 (missing SigV4)
- Signed requests from outside the Organization → explicit Deny
- Only IAM identities within the Org can invoke the API

### Routes

| Method | Path | Lambda | Purpose |
|--------|------|--------|---------|
| POST | /api/policy-analysis/scan | StartScanFn | Start a policy scan workflow |
| GET | /api/policy-analysis/status | GetStatusFn | Poll job progress from DynamoDB |
| GET | /api/policy-analysis/result | GetResultFn | Fetch completed results from S3 |
| POST | /api/iam-federation/discover | StartIamDiscoverFn | Start IAM discovery workflow |
| GET | /api/iam-federation/discover/status | GetStatusFn | Poll discovery job |
| POST | /api/iam-federation/migrate | StartMigrateFn | Start migration workflow |
| GET | /api/iam-federation/migrate/status | GetStatusFn | Poll migration job |
| POST | /api/iam-federation/generate-iac | GenerateIacFn | Generate CloudFormation/Terraform |
| POST | /api/idc/discover | StartIdcDiscoverFn | Start IdC discovery workflow |
| GET | /api/idc/discover/status | GetStatusFn | Poll IdC discovery job |

### Caller Permissions

The user's IAM identity needs only:

```json
{
  "Effect": "Allow",
  "Action": "execute-api:Invoke",
  "Resource": "arn:aws:execute-api:us-east-1:TRUFFLE_ACCOUNT:API_ID/prod/*"
}
```

No direct access to Step Functions, DynamoDB, S3, or target accounts is needed.

---

## Job Orchestration: Step Functions

Step Functions handles the **account × region fanout**. Each account+region
combination is a discrete unit of work dispatched to a Lambda invocation.

### Policy Analysis Workflow

```
StartExecution (input: {accounts, regions, search_terms, services})
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ Map (Accounts)   maxConcurrency: 10 (configurable)  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ Map (Regions)  maxConcurrency: 5              │  │
│  │                                               │  │
│  │  ┌─────────────────────────────────────────┐  │  │
│  │  │ ScanUnit Lambda                         │  │  │
│  │  │  - AssumeRole into target account       │  │  │
│  │  │  - Parallel API calls within the unit   │  │  │
│  │  │    (asyncio, bounded by semaphore)      │  │  │
│  │  │  - Returns matches for this acct+region │  │  │
│  │  └─────────────────────────────────────────┘  │  │
│  │                                               │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ ScanGlobal Lambda (per account)               │  │
│  │  - S3 bucket policies, IAM, Organizations     │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  WriteProgress → DynamoDB (per-account progress)    │
│                                                     │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ AggregateResults Lambda                             │
│  - Merge all matches into a single result set       │
│  - Write final payload to S3                        │
│  - Update DynamoDB job status → "done"              │
└─────────────────────────────────────────────────────┘
```

### IAM Federation Discovery Workflow

```
StartExecution (input: {accounts, idp_filter, role_name})
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ Map (Accounts)   maxConcurrency: 10                 │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │ DiscoverRoles Lambda                        │    │
│  │  - AssumeRole into target                   │    │
│  │  - Paginate all IAM roles (parallel pages)  │    │
│  │  - Filter by SAML trust policy              │    │
│  │  - Enrich with attached/inline policies     │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ AggregateAndStore Lambda                            │
│  - Merge discovered roles                           │
│  - Write to S3 + update DynamoDB                    │
└─────────────────────────────────────────────────────┘
```

### Migration Workflow

```
StartExecution (input: {role_arns, mode, aam_provider_arn})
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ BackupTrustPolicies Lambda                          │
│  - Snapshot current trust policies to S3            │
└──────────────────────────┬──────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────┐
│ Map (Roles)   maxConcurrency: 5 (throttle writes)   │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │ MigrateRole Lambda                          │    │
│  │  - AssumeRole (TruffleRole)                 │    │
│  │  - Check for existing AAM trust statement   │    │
│  │  - ADD or REPLACE trust policy              │    │
│  │  - Log result to DynamoDB                   │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
└─────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────┐
│ WriteMigrationLog Lambda                            │
│  - Summarize results in DynamoDB                    │
└─────────────────────────────────────────────────────┘
```

### Error Handling

Every Lambda invocation in a Map state has:

```json
{
  "Retry": [
    {
      "ErrorEquals": ["Lambda.TooManyRequestsException", "States.TaskFailed"],
      "IntervalSeconds": 5,
      "MaxAttempts": 3,
      "BackoffRate": 2.0
    }
  ],
  "Catch": [
    {
      "ErrorEquals": ["States.ALL"],
      "ResultPath": "$.error",
      "Next": "RecordUnitFailure"
    }
  ]
}
```

Failed units are recorded but don't block other accounts/regions. The final
aggregation reports partial failures to the user.

---

## Lambda: Parallelism Within a Unit

Step Functions handles fanout across accounts and regions. Within a single
Lambda invocation (one account + one region), the scanner still parallelizes
API calls for throughput.

### Why

A single region in one account might have:
- 200 S3 buckets → 200 GetBucketPolicy calls
- 50 SQS queues → 50 GetQueueAttributes calls
- 30 KMS keys → 30 GetKeyPolicy calls

Sequential execution would waste Lambda billable time and hit the 15-minute
timeout on large accounts.

### How

```python
import asyncio
from aiobotocore.session import get_session

CONCURRENCY_PER_SERVICE = 10  # avoid throttling any single API

async def scan_unit(account_id: str, region: str, role_arn: str, search_terms: list[str]):
    """Scan all resource policies in one account + one region."""
    session = await assume_role_async(role_arn)

    results = await asyncio.gather(
        scan_s3_policies(session, region, search_terms),
        scan_sqs_policies(session, region, search_terms),
        scan_kms_policies(session, region, search_terms),
        scan_sns_policies(session, region, search_terms),
        scan_lambda_policies(session, region, search_terms),
        scan_secrets_manager(session, region, search_terms),
        scan_ecr_policies(session, region, search_terms),
        # ... additional services
    )
    return merge_results(results)

async def scan_s3_policies(session, region, search_terms):
    """Fetch all bucket policies concurrently with bounded concurrency."""
    s3 = session.create_client('s3', region_name=region)
    buckets = await list_buckets(s3)

    sem = asyncio.Semaphore(CONCURRENCY_PER_SERVICE)

    async def get_one(bucket):
        async with sem:
            try:
                resp = await s3.get_bucket_policy(Bucket=bucket)
                return analyze_policy(resp['Policy'], search_terms, bucket)
            except s3.exceptions.NoSuchBucketPolicy:
                return None

    return await asyncio.gather(*[get_one(b) for b in buckets], return_exceptions=True)
```

### Key Points

- **Step Functions** = account/region fanout (no parallelism in the client)
- **Lambda (asyncio)** = service/resource fanout within a single unit
- **Semaphore** = per-service concurrency cap to avoid throttling
- **Network advantage** = Lambda → AWS API is ~1-5ms vs ~50-200ms from a laptop

### Lambda Sizing

| Function | Memory | Timeout | Rationale |
|----------|--------|---------|-----------|
| ScanUnit (regional) | 512 MB | 5 min | Bounded by service count per region |
| ScanGlobal | 512 MB | 10 min | S3 bucket enumeration can be slow |
| DiscoverRoles | 1024 MB | 10 min | Paginating thousands of IAM roles |
| MigrateRole | 256 MB | 30 sec | Single IAM API call per role |
| AggregateResults | 1024 MB | 2 min | Merging large result sets in memory |
| StartJob / GetStatus | 128 MB | 10 sec | Simple DynamoDB read/write |

---

## Cross-Account Access: StackSet-Deployed Roles

### Approach

A CloudFormation StackSet deploys IAM roles into every target account that
Truffle needs to scan or migrate. This is a one-time setup by the customer's
platform/infra team.

A single role is deployed:

| Role | Purpose | Permissions |
|------|---------|-------------|
| `TruffleRole` | Scanning, discovery, and migration | `ReadOnlyAccess` + `iam:UpdateAssumeRolePolicy` |

Read operations (scan, discovery) use only the read-only permissions. The
`iam:UpdateAssumeRolePolicy` permission is only exercised during an explicit
migration workflow — no write calls happen during scans.

### Trust Relationship

The role trusts only the Lambda execution role in the Truffle backend account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::TRUFFLE_ACCOUNT:role/TruffleLambdaExecRole"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "${ExternalId}"
        }
      }
    }
  ]
}
```

### StackSet Template

```yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: >
  Truffle cross-account role — deployed via StackSet to all target accounts.

Parameters:
  TruffleAccountId:
    Type: String
    Description: AWS account ID hosting the Truffle managed backend
  ExternalId:
    Type: String
    Description: Shared external ID for confused-deputy protection
    NoEcho: true

Resources:
  TruffleRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: TruffleRole
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${TruffleAccountId}:role/TruffleLambdaExecRole"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
      Policies:
        - PolicyName: TruffleMigratePolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - iam:UpdateAssumeRolePolicy
                Resource: "*"
      Tags:
        - Key: ManagedBy
          Value: Truffle

Outputs:
  RoleArn:
    Value: !GetAtt TruffleRole.Arn
```

### How Lambdas Use the Role

```python
import boto3

def assume_truffle_role(account_id: str, external_id: str, operation: str = "scan"):
    """Assume the Truffle role in a target account."""
    sts = boto3.client("sts")
    resp = sts.assume_role(
        RoleArn=f"arn:aws:iam::{account_id}:role/TruffleRole",
        RoleSessionName=f"truffle-{operation}-{account_id}",
        ExternalId=external_id,
        DurationSeconds=3600,
    )
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
```

### Security Controls

| Control | Purpose |
|---------|---------|
| External ID | Prevents confused-deputy attacks |
| Trust scoped to specific role ARN | Only `TruffleLambdaExecRole` can assume — not the whole account |
| Least privilege | ReadOnlyAccess + only `iam:UpdateAssumeRolePolicy` for migration |
| Short-lived credentials | STS tokens expire in 1 hour max |
| Role session name | Set to `truffle-<operation>-<account_id>` for CloudTrail auditability |
| StackSet deployment | Centrally managed — role can be revoked org-wide in one operation |

---

## State & Progress: DynamoDB

### Jobs Table

| Attribute | Type | Description |
|-----------|------|-------------|
| PK | `CALLER#<iam-arn>` | Caller's IAM ARN (from SigV4 context) |
| SK | `JOB#<job_id>` | Unique job identifier |
| type | String | `policy-scan`, `iam-discover`, `iam-migrate`, `idc-discover` |
| status | String | `running`, `done`, `error` |
| progress | Map | `{completed_units, total_units, message}` |
| started_at | String (ISO) | Job start timestamp |
| finished_at | String (ISO) | Job completion timestamp |
| result_key | String | S3 key for the full result payload |
| error | String | Error message if failed |
| TTL | Number | Auto-expire old jobs after 30 days |

Jobs are keyed by the caller's IAM ARN (extracted from the API Gateway request
context). This provides natural isolation — each caller sees only their own jobs
without needing a separate user management system.

### Migration Log Table

| Attribute | Type | Description |
|-----------|------|-------------|
| PK | `CALLER#<iam-arn>` | Caller's IAM ARN |
| SK | `MIGRATE#<timestamp>#<role_arn>` | Per-role entry |
| status | String | `success`, `skipped`, `error` |
| mode | String | `ADD` or `REPLACE` |
| error | String | Error detail if failed |
| previous_trust_policy | Map | Backup for rollback |

---

## Results Storage: S3

| Bucket | Purpose |
|--------|---------|
| `truffle-results-<account_id>` | Stores scan results, discovery data, IaC templates |

Object key pattern: `callers/<iam-arn-hash>/policy-analysis/<job_id>.json`

Results are read by the GetResult Lambda and returned through the API. No
pre-signed URLs are needed since the client never talks to S3 directly.

---

## Auth Flow: End-to-End

```
1. User runs: TRUFFLE_MODE=managed TRUFFLE_API_ENDPOINT=https://xxx.execute-api.us-east-1.amazonaws.com/prod python app.py
2. Flask starts on localhost with managed mode enabled
3. User opens UI in browser → React app loads from localhost
4. User configures a scan and clicks "Start"
5. React → POST localhost:5000/api/policy-analysis/scan
6. Flask (_jobs_managed.py) → resolves local AWS creds (SSO/profile/env)
7. Flask → SigV4-signs the request → POST https://xxx.execute-api.../prod/api/policy-analysis/scan
8. API Gateway validates SigV4 + resource policy (org check) → allows
9. StartScanFn Lambda → writes job to DynamoDB → starts Step Functions execution → returns {job_id}
10. React polls localhost:5000/api/policy-analysis/status?job=xxx every 5s
11. Flask signs each poll → API Gateway → GetStatusFn → DynamoDB → returns progress
12. Step Functions completes → AggregateResults writes to S3, marks job "done"
13. React fetches results → Flask → API Gateway → GetResultFn → S3 → returns payload
```

---

## Deployment Structure (CDK)

```
managed-solution/
├── bin/
│   └── app.ts                       # CDK app entry point
├── lib/
│   ├── api-stack.ts                 # API Gateway (Regional, IAM auth) + Lambda functions
│   ├── workflow-stack.ts            # Step Functions state machines
│   ├── storage-stack.ts             # DynamoDB tables + S3 results bucket
│   └── cross-account-stack.ts       # StackSet template for target account roles
├── lambda/
│   ├── start-job/                   # Start Step Functions execution
│   ├── get-status/                  # Read DynamoDB job status
│   ├── get-result/                  # Read results from S3
│   ├── scan-unit/                   # Scan one account+region (async parallel)
│   ├── scan-global/                 # Scan global services for one account
│   ├── discover-roles/              # IAM Federation discovery for one account
│   ├── migrate-role/                # Update trust policy for one role
│   ├── aggregate/                   # Merge results, write to S3
│   └── shared/                      # Credential resolution, utils
├── state-machines/
│   ├── policy-scan.asl.json
│   ├── iam-discover.asl.json
│   └── iam-migrate.asl.json
├── stackset-templates/
│   └── truffle-target-roles.yaml    # Cross-account role StackSet
└── cdk.json
```

Note: No frontend hosting infrastructure (no CloudFront, S3 static hosting, or
Cognito stacks). The UI runs locally.

---

## Scalability

| Dimension | Mechanism | Limit |
|-----------|-----------|-------|
| Concurrent callers | API Gateway auto-scales | 10,000 RPS (default) |
| Accounts per scan | Step Functions Map state | Configurable (default 10 concurrent) |
| Regions per account | Nested Map state | All enabled regions in parallel |
| Resources per region | Lambda asyncio with semaphore | Bounded by memory + timeout |
| Job duration | Step Functions Standard | Up to 1 year |
| Results storage | S3 | Unlimited |

---

## Cost Estimate (1,000 accounts x 5 regions x 2,000 resources)

| Component | Calculation | Cost per run |
|-----------|-------------|-------------|
| Step Functions | ~12,000 state transitions x $0.025/1K | $0.30 |
| Lambda (scan) | 6,000 invocations x 60s avg x 0.5 GB | $3.00 |
| Lambda (API) | ~100 invocations x 0.1s x 128 MB | < $0.01 |
| DynamoDB | ~12,000 writes + reads | $0.02 |
| S3 | Result objects + storage | $0.01 |
| API Gateway | ~100 requests x $1/million | < $0.01 |
| **Total per scan** | | **~$3.35** |

No CloudFront, Cognito, or WAF costs.

---

## Security Summary

| Layer | Control |
|-------|---------|
| API access | IAM SigV4 on every request + resource policy (org-scoped) |
| No public UI | Frontend runs on localhost only |
| Cross-account | Least-privilege StackSet role with external ID |
| Data isolation | DynamoDB keyed by caller IAM ARN |
| Encryption at rest | S3 SSE-S3, DynamoDB encryption enabled |
| Encryption in transit | TLS everywhere (HTTPS to API Gateway, HTTPS to AWS APIs from Lambda) |
| No stored secrets | All credential resolution via IAM roles and STS |
| Audit | CloudTrail logs all API Gateway calls and cross-account AssumeRole |

---

## Resilience & Recovery

| Scenario | Handling |
|----------|----------|
| Lambda timeout on one unit | Step Functions retries with exponential backoff (3 attempts) |
| Partial scan failure | Map state tolerates failures; successful units preserved |
| User closes browser mid-scan | Job continues in Step Functions; user re-opens UI and polls status |
| AWS API throttling | SDK adaptive retry + asyncio semaphore limits concurrent calls |
| Need to rollback migration | Trust policy backups stored in S3; re-run with original policy |
| Full scan re-run | Idempotent — read-only scans just refresh data |

---

## Comparison: Local Mode vs Managed Mode

| | Local Mode | Managed Mode |
|---|---|---|
| Where scanning runs | User's machine (threads) | AWS Lambda (asyncio) |
| Account/region parallelism | ThreadPoolExecutor in Python | Step Functions Map states |
| Within-unit parallelism | ThreadPoolExecutor (same) | asyncio + semaphore (same pattern) |
| Credential source | User's local AWS creds directly | Lambda exec role → AssumeRole into targets |
| Resilience | Checkpoint files for resume | Step Functions retry + catch |
| Network latency to APIs | 50-200ms per call | 1-5ms per call |
| Max scan duration | Until machine sleeps / process killed | Up to 1 year (Step Functions) |
| Setup required | Just AWS creds | Deploy backend stack + StackSet roles |
| Multi-user support | No (single machine) | Yes (isolated by IAM ARN) |

Both modes use the same UI, same Flask routes, and same API contract. The user
selects the mode at launch with a single environment variable.
