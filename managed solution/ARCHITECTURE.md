# Truffle — Managed Serverless Architecture

This document describes the design and architecture for deploying the Truffle AAM Migration Console as a managed, multi-tenant serverless solution on AWS.

---

## Design Goals

| Goal | Approach |
|------|----------|
| Fast | CloudFront edge caching for static assets; Lambda concurrency for parallel scanning |
| Resilient to long-running jobs (hours) | Step Functions Standard Workflows (up to 1-year execution) |
| State preserved across tab switches | Job state in DynamoDB, frontend reconnects via job ID |
| Cost-effective at enterprise scale | Pay-per-request pricing across all components |
| No infrastructure to manage | Fully serverless — no EC2, no containers |
| Multi-user | Cognito authentication; jobs isolated per user |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              End Users                                   │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ HTTPS
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Amazon CloudFront                                │
│  ┌───────────────────────┐     ┌────────────────────────────────────┐   │
│  │  S3 Origin (React UI) │     │  API Gateway Origin (/api/*)       │   │
│  └───────────────────────┘     └────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
         ┌──────────────┐  ┌───────────┐  ┌───────────────┐
         │  API Gateway  │  │ Cognito   │  │ S3 (UI dist)  │
         │  (HTTP API)   │  │ User Pool │  │               │
         └──────┬───────┘  └───────────┘  └───────────────┘
                │
    ┌───────────┼───────────────────┐
    ▼           ▼                   ▼
┌────────┐ ┌────────────┐   ┌──────────────┐
│ Lambda │ │ Lambda     │   │ Lambda       │
│ (CRUD) │ │ (Start Job)│   │ (Get Status) │
└────────┘ └─────┬──────┘   └──────┬───────┘
                 │                  │
                 ▼                  ▼
        ┌────────────────┐  ┌─────────────┐
        │ Step Functions │  │  DynamoDB   │
        │ (Standard)     │  │  (Jobs)     │
        └───────┬────────┘  └─────────────┘
                │
    ┌───────────┼───────────────────┐
    ▼           ▼                   ▼
┌────────┐ ┌────────────┐   ┌──────────────┐
│ Lambda │ │ Lambda     │   │ Lambda       │
│ (Scan  │ │ (Scan      │   │ (Aggregate)  │
│ Global)│ │ Regional)  │   │              │
└────────┘ └────────────┘   └──────┬───────┘
                                    │
                                    ▼
                            ┌──────────────┐
                            │  S3 (Results)│
                            └──────────────┘
```

---

## Component Details

### 1. Static Frontend — S3 + CloudFront

| Component | Purpose |
|-----------|---------|
| S3 bucket | Hosts the built React/Cloudscape SPA (`web/dist`) |
| CloudFront distribution | Global edge caching, HTTPS termination, custom domain |
| Origin Access Control | S3 bucket is private; only CloudFront can read it |

The CloudFront distribution has two origins:
- **Default (`/*`)** — S3 bucket for the React app (SPA fallback to `index.html`)
- **API (`/api/*`)** — API Gateway HTTP API

### 2. Authentication — Amazon Cognito

| Component | Purpose |
|-----------|---------|
| Cognito User Pool | User registration, login, MFA |
| Cognito Hosted UI or custom | Login flow integrated into the React app |
| JWT authorizer on API Gateway | Validates access tokens on every /api/* request |

Each user's jobs and results are namespaced by their Cognito `sub` (user ID).

### 3. API Layer — API Gateway (HTTP API)

Lightweight HTTP API with JWT authorization. Routes:

| Method | Path | Lambda | Purpose |
|--------|------|--------|---------|
| GET | /api/health | HealthFn | Liveness check |
| POST | /api/policy-analysis/scan | StartPolicyScanFn | Start a policy scan workflow |
| GET | /api/policy-analysis/status | GetJobStatusFn | Poll job progress from DynamoDB |
| GET | /api/policy-analysis/result | GetResultFn | Fetch completed results from S3 |
| POST | /api/iam-federation/providers | IamProvidersFn | List SAML providers |
| POST | /api/iam-federation/discover | StartIamDiscoverFn | Start IAM discovery workflow |
| GET | /api/iam-federation/discover/status | GetJobStatusFn | Poll job progress |
| POST | /api/iam-federation/migrate | StartMigrateFn | Start migration workflow |
| POST | /api/iam-federation/generate-iac | GenerateIacFn | Generate CloudFormation/Terraform |
| GET | /api/iam-federation/log | GetMigrationLogFn | Fetch migration log from DynamoDB |
| POST | /api/idc/discover | StartIdcDiscoverFn | Start IdC discovery workflow |

### 4. Job Orchestration — Step Functions (Standard Workflows)

Standard Workflows handle multi-hour executions with built-in retry, parallelism, and state persistence.

#### Policy Analysis Workflow

```
StartExecution
    │
    ▼
┌─────────────────────────┐
│ ResolveCredentials      │  (Lambda: resolve sessions per account)
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Map (Accounts)          │  maxConcurrency: configurable (default 10)
│  ┌────────────────────┐ │
│  │ ScanGlobal         │ │  (Lambda: scan global services for one account)
│  └────────────────────┘ │
│  ┌────────────────────┐ │
│  │ Map (Regions)      │ │  maxConcurrency: configurable (default 5)
│  │  └─ ScanRegional   │ │  (Lambda: scan regional services for one region)
│  └────────────────────┘ │
│  ┌────────────────────┐ │
│  │ WriteProgress      │ │  (DynamoDB: update per-account progress)
│  └────────────────────┘ │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ AggregateResults        │  (Lambda: merge matches, write to S3)
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ MarkJobComplete         │  (DynamoDB: set status = done)
└─────────────────────────┘
```

#### IAM Federation Discovery Workflow

```
StartExecution
    │
    ▼
┌─────────────────────────┐
│ ResolveCredentials      │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Map (Accounts)          │
│  ┌────────────────────┐ │
│  │ ListRoles          │ │  (Lambda: paginate all IAM roles)
│  └────────────────────┘ │
│  ┌────────────────────┐ │
│  │ FilterSAMLRoles    │ │  (Lambda: inspect trust policies, filter by IDP)
│  └────────────────────┘ │
│  ┌────────────────────┐ │
│  │ EnrichPolicies     │ │  (Lambda: get attached/inline policies per role)
│  └────────────────────┘ │
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ AggregateAndStore       │  (Lambda: merge, write to S3 + DynamoDB)
└─────────────────────────┘
```

#### Migration Workflow

```
StartExecution (with role ARNs + mode)
    │
    ▼
┌─────────────────────────┐
│ BackupTrustPolicies     │  (Lambda: snapshot current policies to S3)
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ Map (Roles)             │  maxConcurrency: 5 (throttle IAM writes)
│  └─ UpdateTrustPolicy   │  (Lambda: ADD or REPLACE, log result to DynamoDB)
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│ WriteMigrationLog       │  (DynamoDB: summary of results)
└─────────────────────────┘
```

### 5. State & Progress — DynamoDB

**Jobs table:**

| Attribute | Type | Description |
|-----------|------|-------------|
| PK | `USER#<sub>` | Cognito user ID |
| SK | `JOB#<job_id>` | Unique job identifier |
| type | String | `policy-scan`, `iam-discover`, `iam-migrate` |
| status | String | `running`, `done`, `error` |
| progress | Map | `{completed_units, total_units, roles_scanned, roles_total, activity}` |
| started_at | String (ISO) | Job start timestamp |
| finished_at | String (ISO) | Job completion timestamp |
| result_key | String | S3 key for the full result payload |
| error | String | Error message if failed |
| TTL | Number | Auto-expire old jobs after 30 days |

**Migration Log table:**

| Attribute | Type | Description |
|-----------|------|-------------|
| PK | `USER#<sub>` | Cognito user ID |
| SK | `MIGRATE#<timestamp>#<role_arn>` | Per-role entry |
| status | String | `success`, `skipped`, `error` |
| mode | String | `ADD` or `REPLACE` |
| error | String | Error detail if failed |
| previous_trust_policy | Map | Backup for rollback |

### 6. Results Storage — S3

| Bucket | Purpose |
|--------|---------|
| `truffle-results-<account>` | Stores scan results, discovery dumps, IaC templates |

Object key pattern: `users/<sub>/policy-analysis/<job_id>.json`

Results are pre-signed for frontend download or read through the API.

### 7. Cross-Account Access

For the assume-role authentication method:

```
┌───────────────────────┐         ┌───────────────────────┐
│  Truffle Account      │         │  Target Account       │
│                       │         │                       │
│  Lambda Execution     │ ──STS──▶│  TruffleReadOnlyRole  │
│  Role                 │  Assume │                       │
│                       │         │  - iam:List*          │
│                       │         │  - iam:Get*           │
│                       │         │  - s3:GetBucket*      │
│                       │         │  - organizations:*    │
│                       │         │  - (service-specific  │
│                       │         │     read permissions) │
└───────────────────────┘         └───────────────────────┘
```

For the migration workflow, the target role additionally needs:
- `iam:UpdateAssumeRolePolicy`

---

## Deployment Architecture

### Infrastructure as Code (CDK)

```
managed-solution/
├── bin/
│   └── app.ts                    # CDK app entry point
├── lib/
│   ├── frontend-stack.ts         # S3 + CloudFront + Cognito
│   ├── api-stack.ts              # API Gateway + Lambda functions
│   ├── workflow-stack.ts         # Step Functions state machines
│   ├── storage-stack.ts          # DynamoDB tables + S3 results bucket
│   └── cross-account-stack.ts   # Stackset for target account roles
├── lambda/
│   ├── scan-global/              # Policy scan — global services
│   ├── scan-regional/            # Policy scan — regional services
│   ├── iam-discover/             # IAM Federation — role discovery
│   ├── iam-migrate/              # IAM Federation — trust policy update
│   ├── aggregate/                # Merge results, write to S3
│   ├── start-job/                # Start Step Functions execution
│   ├── get-status/               # Read DynamoDB job status
│   └── shared/                   # Shared utilities (credential resolution)
├── state-machines/
│   ├── policy-scan.asl.json      # Policy scan workflow definition
│   ├── iam-discover.asl.json     # IAM discovery workflow definition
│   └── iam-migrate.asl.json      # Migration workflow definition
└── cdk.json
```

### Environments

| Environment | Purpose | Account |
|-------------|---------|---------|
| Dev | Development and testing | Dedicated dev account |
| Staging | Pre-production validation | Shared services account |
| Production | Customer-facing | Production account |

---

## Scalability Characteristics

| Dimension | Scaling mechanism | Limit |
|-----------|-------------------|-------|
| Concurrent users | API Gateway scales automatically | 10,000 RPS default |
| Accounts per scan | Step Functions Map state parallelism | Configurable (1–40 concurrent) |
| Regions per account | Nested Map state | All enabled regions in parallel |
| Resources per region | Lambda memory + timeout | 10 GB / 15 min per invocation |
| Job duration | Step Functions Standard | Up to 1 year |
| Results storage | S3 | Unlimited |

### Lambda Sizing Recommendations

| Function | Memory | Timeout | Rationale |
|----------|--------|---------|-----------|
| ScanGlobal | 512 MB | 10 min | S3 bucket enumeration can be slow |
| ScanRegional | 512 MB | 5 min | Bounded by region service count |
| IamDiscover | 1024 MB | 10 min | Paginating thousands of roles |
| IamMigrate | 256 MB | 30 sec | Single IAM API call per role |
| Aggregate | 1024 MB | 2 min | Merging large result sets |
| StartJob / GetStatus | 128 MB | 10 sec | Simple DynamoDB reads/writes |

---

## Cost Estimate (1,000 accounts × 5 regions × 2,000 resources)

| Component | Calculation | Cost per run |
|-----------|-------------|-------------|
| Step Functions | ~12,000 state transitions × $0.025/1K | $0.30 |
| Lambda (scan) | 6,000 invocations × 60s avg × 0.5 GB | $3.00 |
| Lambda (API) | ~4,000 invocations × 0.1s × 128 MB | $0.01 |
| DynamoDB | ~12,000 writes + ~4,000 reads | $0.02 |
| S3 | ~10 PutObject + storage | $0.01 |
| API Gateway | ~4,000 requests × $1/million | $0.004 |
| CloudFront | Static assets cached | $0.01 |
| **Total per scan** | | **~$3.35** |

Monthly cost at once-daily runs: **~$100/month**
Monthly cost at weekly runs: **~$14/month**

---

## Security

| Layer | Control |
|-------|---------|
| Network | CloudFront + API Gateway — no direct Lambda exposure |
| Authentication | Cognito JWT tokens on every API request |
| Authorization | User-scoped DynamoDB keys prevent cross-user access |
| Cross-account | Least-privilege IAM roles in target accounts |
| Encryption at rest | S3 SSE-S3, DynamoDB encryption enabled |
| Encryption in transit | TLS everywhere (CloudFront → API GW → Lambda) |
| Secrets | No secrets stored — all credential resolution via IAM roles |
| Audit | CloudTrail logs all IAM mutations; Step Functions execution history |

---

## Resilience & Recovery

| Scenario | Handling |
|----------|----------|
| Lambda timeout on a single unit | Step Functions retries with exponential backoff (3 attempts) |
| Partial scan failure | Map state `tolerated failure` threshold; successful units are preserved |
| User closes browser mid-scan | Job continues in Step Functions; frontend reconnects via job ID |
| Server-side error | DynamoDB stores error state; user can re-run (idempotent) |
| Need to rollback migration | Trust policy backups stored in S3; rollback Lambda available |

---

## Migration Path (Local → Managed)

1. **Phase 1:** Deploy the static frontend to CloudFront + S3. Keep the API running locally for testing.
2. **Phase 2:** Deploy the API Gateway + Lambda functions. Point the frontend at the managed API.
3. **Phase 3:** Replace the thread-based job runner with Step Functions workflows.
4. **Phase 4:** Add Cognito for multi-user authentication.
5. **Phase 5:** Deploy CloudFormation StackSets for cross-account roles in target accounts.

Each phase is independently deployable and testable. The frontend doesn't change between phases — only the API endpoint it targets.


---

## Deep Dive: Cross-Account Access

### How It Works

The Truffle managed solution uses **IAM role chaining** to access customer accounts. The scan/discovery/migration Lambdas in the Truffle account call `sts:AssumeRole` to obtain temporary credentials in each target account.

```
┌─────────────────────────────┐           ┌──────────────────────────────┐
│  Truffle Account (central)  │           │  Customer Account (target)   │
│                             │           │                              │
│  Lambda Execution Role      │──AssumeRole──▶ TruffleScanRole          │
│  arn:aws:iam::TRUFFLE:role/ │           │  arn:aws:iam::CUSTOMER:role/ │
│    TruffleLambdaExecRole    │           │    TruffleScanRole           │
│                             │           │                              │
│  Trust: lambda.amazonaws.com│           │  Trust: arn:aws:iam::TRUFFLE │
│  Permissions:               │           │    :role/TruffleLambdaExec   │
│    sts:AssumeRole on        │           │                              │
│    arn:aws:iam::*:role/     │           │  Permissions:                │
│      TruffleScanRole        │           │    iam:List*, iam:Get*       │
│                             │           │    s3:GetBucket*, s3:List*   │
│                             │           │    organizations:Describe*   │
│                             │           │    organizations:List*       │
│                             │           │    (service-specific reads)  │
└─────────────────────────────┘           └──────────────────────────────┘
```

For the **migration** workflow, a separate role with write permissions is used:

```
TruffleMigrateRole (target account)
  Trust: arn:aws:iam::TRUFFLE:role/TruffleLambdaExecRole
  Condition: sts:ExternalId = <customer-provided-secret>
  Permissions:
    iam:GetRole
    iam:UpdateAssumeRolePolicy
```

### Customer Requirements

To enable Truffle to scan or migrate their accounts, the customer must:

| Requirement | Detail |
|-------------|--------|
| **1. Deploy IAM roles in target accounts** | A `TruffleScanRole` (read-only) and optionally `TruffleMigrateRole` (write) in each account to be scanned/migrated. |
| **2. Trust the Truffle central account** | The role trust policy must allow `sts:AssumeRole` from the Truffle Lambda execution role ARN. |
| **3. Use an external ID (recommended)** | An `sts:ExternalId` condition in the trust policy prevents confused-deputy attacks. The customer provides their unique external ID during onboarding; Truffle passes it on every AssumeRole call. |
| **4. Scope permissions appropriately** | Read-only role gets only List/Get/Describe. Migration role gets only `iam:UpdateAssumeRolePolicy`. No admin access. |
| **5. Deploy via StackSet or Terraform** | For multi-account, the customer deploys the role to all target accounts via CloudFormation StackSets (org-level) or Terraform. We provide the template. |

### Provided Deployment Templates

We provide customers with ready-to-deploy templates:

**CloudFormation (StackSet-compatible):**

```yaml
Parameters:
  TruffleAccountId:
    Type: String
    Description: The AWS account ID of the Truffle managed solution
  ExternalId:
    Type: String
    Description: Your unique external ID (provided during onboarding)
    NoEcho: true

Resources:
  TruffleScanRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: TruffleScanRole
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
      Tags:
        - Key: ManagedBy
          Value: Truffle
```

### Security Controls on Cross-Account Access

| Control | Purpose |
|---------|---------|
| External ID | Prevents confused-deputy attacks |
| Explicit trust to specific role ARN | Only the Truffle Lambda role can assume (not the whole account) |
| Least privilege | Read-only for scanning; write scoped to `iam:UpdateAssumeRolePolicy` only for migration |
| No persistent credentials | All access via short-lived STS tokens (1-hour max) |
| CloudTrail | Every AssumeRole call is logged in both accounts |
| Role session name | Set to `truffle-<job_id>` for auditability |

---

## Deep Dive: Failure Handling & Resilience

### Step Functions Error Handling Strategy

Every unit of work (one account × one region, or one role) is an individual Lambda invocation wrapped in Step Functions error handling:

```json
{
  "ScanRegional": {
    "Type": "Task",
    "Resource": "arn:aws:lambda:...:scan-regional",
    "Retry": [
      {
        "ErrorEquals": ["Lambda.TooManyRequestsException", "States.TaskFailed"],
        "IntervalSeconds": 5,
        "MaxAttempts": 3,
        "BackoffRate": 2.0
      },
      {
        "ErrorEquals": ["States.Timeout"],
        "IntervalSeconds": 30,
        "MaxAttempts": 2,
        "BackoffRate": 1.5
      }
    ],
    "Catch": [
      {
        "ErrorEquals": ["States.ALL"],
        "ResultPath": "$.error",
        "Next": "RecordUnitFailure"
      }
    ],
    "TimeoutSeconds": 600
  }
}
```

### Failure Scenarios & Responses

| Scenario | Detection | Response | User Impact |
|----------|-----------|----------|-------------|
| **Single region timeout** | Lambda exceeds 10-min timeout | Step Functions catches `States.Timeout`, retries twice with 30s/45s backoff. If still failing, catches error and records partial failure. | Other regions/accounts proceed; user sees "partial" status on that account. |
| **API rate limiting (throttling)** | `TooManyRequestsException` or `Throttling` from AWS SDK | Retry with exponential backoff: 5s → 10s → 20s (3 attempts). Lambda itself also has SDK-level retries with jitter. | Transparent to user — most throttles resolve within the retry window. |
| **Account credential failure** | `AccessDenied` or `ExpiredToken` | Caught immediately, no retry (not transient). Recorded as account-level error. | User sees the specific account marked as "error" with the reason. Other accounts continue. |
| **Single role migration failure** | IAM API error on UpdateAssumeRolePolicy | Caught per-role. Logged as `error` in migration log. Other roles continue. | User sees per-role status: success/skipped/error with detail. |
| **Lambda OOM or crash** | `States.TaskFailed` | Retried up to 3 times. If persistent, caught and recorded. | Rare — Lambda memory is sized generously. |
| **Step Functions service error** | `States.Runtime` | Built-in SF retry. Extremely rare. | User can re-run; completed units are idempotent. |

### Rate Limit Mitigation (Preventive)

Beyond reactive retries, we proactively prevent throttling:

| Technique | Implementation |
|-----------|---------------|
| **Controlled parallelism** | Map state `MaxConcurrency` limits concurrent account scans (default: 10). Prevents stampeding 1,000 accounts simultaneously. |
| **Per-service concurrency** | Within a Lambda, the scanner uses a thread pool (max 5 workers per service) — same as the local tool. |
| **Staggered start** | Map iterations start with a small random jitter (0–2s) to avoid synchronized bursts. |
| **SDK retry with jitter** | boto3 configured with `adaptive` retry mode — automatically handles throttling with full jitter backoff. |
| **Regional spread** | Different regions hit different API endpoints, naturally distributing load. |

### Partial Results & Resume

If a scan completes with some failed units:

1. **Successful units are preserved** — results from completed account/region combinations are stored in S3 and reflected in the final output.
2. **Failed units are flagged** — the job status shows `status: "done"` with a `partial: true` flag and a list of failed units.
3. **Re-run is safe** — a re-run of the same scan parameters will re-scan all units (no server-side checkpoint for the managed version, since Step Functions handles the retry logic internally). Completed migrations are idempotent (the AAM trust Sid is checked before update).

### Idempotency Guarantees

| Operation | Idempotent? | Mechanism |
|-----------|-------------|-----------|
| Policy scan | Yes | Read-only; repeated scans just refresh data |
| Role discovery | Yes | Read-only |
| Trust policy migration (ADD) | Yes | Checks for existing `AAMTrustPolicyStatement` Sid before adding |
| Trust policy migration (REPLACE) | Yes | Same Sid check |
| IaC generation | Yes | Pure computation from cached data |

---

## Deep Dive: Frontend Security (CloudFront)

### The Concern

A public CloudFront distribution means anyone with the URL could potentially access the application. For an internal migration tool that operates on IAM trust policies, this is unacceptable.

### Solution: CloudFront + Cognito + API Gateway Authorization

We use the standard AWS pattern for securing single-page applications:

```
                    ┌─────────────────────┐
                    │  User's Browser     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  CloudFront         │
                    │  (public endpoint)  │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                                 ▼
    ┌──────────────────┐              ┌──────────────────┐
    │  S3 (static UI)  │              │  API Gateway     │
    │  (public assets) │              │  (/api/*)        │
    │  - HTML/JS/CSS   │              │                  │
    │  - No sensitive   │              │  JWT Authorizer  │◀── Cognito
    │    data           │              │  (EVERY request) │    User Pool
    └──────────────────┘              └──────────────────┘
```

### Security Layers

| Layer | What It Does | Why It's Secure |
|-------|-------------|-----------------|
| **CloudFront → S3** | Serves the React bundle (HTML, JS, CSS) | These are **static build artifacts** — they contain no secrets, no data, no API keys. Even if someone loads the page unauthenticated, they see a login screen and nothing else. |
| **Cognito Authentication** | User must sign in before the app is functional | The React app redirects to Cognito hosted UI (or embedded login). No API calls are possible without a valid JWT. |
| **API Gateway JWT Authorizer** | Validates the Cognito access token on every `/api/*` request | Without a valid, non-expired token signed by the Cognito User Pool, API Gateway returns 401. The Lambda never executes. |
| **Token scoping** | Each user's jobs/data are namespaced by Cognito `sub` | Even with a valid token, User A cannot access User B's scan results. |

### Why This Pattern Is Standard and Secure

This is the [AWS-recommended pattern](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-react-based-single-page-application-to-amazon-s3-and-cloudfront.html) for serverless SPAs. It's used by:
- AWS Console itself (CloudFront + auth)
- AWS Amplify hosted apps
- Most SaaS products on AWS

The static assets being "public" is not a vulnerability because:
1. **The JavaScript bundle is the UI shell** — it renders a login form. It cannot access any data without a token.
2. **All sensitive operations are behind the API** — which requires authentication.
3. **There are no embedded secrets** — credentials are resolved server-side via IAM roles.

### Additional Hardening Options

If even the login page being publicly accessible is a concern, we have options:

| Option | Trade-off |
|--------|-----------|
| **CloudFront + WAF with IP allowlist** | Restrict CloudFront to corporate IP ranges. Simple but breaks remote/VPN users. |
| **CloudFront + Lambda@Edge auth** | Lambda@Edge checks for a valid session cookie before serving any static asset. Unauthorized users see nothing — not even the login page. |
| **AWS Verified Access** | Place the entire app behind Verified Access with IdP integration (Okta, Entra, etc.). Zero-trust network access — only authenticated, posture-checked devices see the app. |
| **Private CloudFront + VPN** | CloudFront with a custom origin access policy that only responds to requests from a VPN or AWS PrivateLink. Heaviest; enterprise-grade. |
| **Cognito + hosted UI with SAML/OIDC** | Federate Cognito with the customer's corporate IdP (Okta, Entra, etc.). Login is via their existing SSO — no separate password. |

### Recommended Approach

For this tool, I'd recommend:

1. **Cognito User Pool federated with the customer's corporate IdP** (SAML or OIDC) — no standalone passwords, users authenticate with their existing corporate credentials.
2. **Lambda@Edge session check** on CloudFront — unauthenticated requests to any path (including static assets) get redirected to the Cognito login flow. Unauthorized users cannot even load the JavaScript bundle.
3. **WAF on CloudFront** with:
   - Rate limiting (prevent brute-force)
   - Geographic restrictions (if applicable)
   - AWS Managed Rules (SQLi, XSS — defense in depth even though this is a SPA)

This gives you a zero-trust posture: the app is invisible to anyone who isn't authenticated through the corporate IdP, and even authenticated users can only access their own data.
