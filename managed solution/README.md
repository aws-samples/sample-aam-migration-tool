# Truffle — Managed Solution

Serverless backend for the Truffle AAM Migration Console. Deploys API Gateway,
Lambda, Step Functions, DynamoDB, and S3 into a central AWS account. The local
UI submits jobs here instead of scanning directly from the user's machine.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Node.js | >= 18 |
| Python | >= 3.11 |
| pip | any recent |
| AWS CDK CLI | >= 2.150 (`npm install -g aws-cdk`) |
| AWS credentials | Admin access to the deployment account |

---

## Quick Deploy

```bash
cd "managed solution"

# Set your org ID and a secure external ID
export TRUFFLE_ORG_ID="o-your-org-id"
export TRUFFLE_EXTERNAL_ID="your-secure-random-string"

# Deploy everything
./deploy.sh
```

Or with a specific AWS profile:

```bash
./deploy.sh --profile truffle-deploy
```

The script handles:
1. Installing Node dependencies
2. Building the custom boto3 Lambda Layer (preview AAM SDK)
3. Compiling TypeScript
4. Bootstrapping CDK (if needed)
5. Deploying all three stacks (Storage, Workflow, API)

---

## Deployment Steps (Manual)

If you prefer to run steps individually:

```bash
cd "managed solution"

# 1. Install dependencies
npm install

# 2. Build the custom boto3 layer
cd layers/custom-boto3
./build.sh
cd ../..

# 3. Compile TypeScript
npx tsc

# 4. Bootstrap CDK (first time only)
npx cdk bootstrap

# 5. Deploy
npx cdk deploy --all \
  --context orgId="o-your-org-id" \
  --context externalId="your-secure-random-string"
```

---

## After Deployment

### 1. Note the API Endpoint

The deploy outputs a URL like:

```
TruffleApiStack.ApiEndpoint = https://abc123xyz.execute-api.us-east-1.amazonaws.com/prod/
```

This is your `TRUFFLE_API_ENDPOINT`.

### 2. Deploy Cross-Account Roles (StackSet)

Target accounts need a `TruffleRole` so the backend can scan/migrate them.
Deploy the StackSet template from your management account:

```bash
aws cloudformation create-stack-set \
  --stack-set-name TruffleTargetRoles \
  --template-body file://stackset-templates/truffle-target-roles.yaml \
  --parameters \
    ParameterKey=TruffleAccountId,ParameterValue=<YOUR_TRUFFLE_ACCOUNT_ID> \
    ParameterKey=ExternalId,ParameterValue=<SAME_EXTERNAL_ID_AS_DEPLOY> \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM

# Deploy to all accounts in the org (or specific OUs)
aws cloudformation create-stack-instances \
  --stack-set-name TruffleTargetRoles \
  --deployment-targets OrganizationalUnitIds=<YOUR_ROOT_OU_ID> \
  --regions us-east-1
```

Or deploy to specific accounts:

```bash
aws cloudformation create-stack-instances \
  --stack-set-name TruffleTargetRoles \
  --accounts 111111111111 222222222222 333333333333 \
  --regions us-east-1
```

### 3. Grant Callers API Access

Each user who will invoke the Truffle API needs:

```json
{
  "Effect": "Allow",
  "Action": "execute-api:Invoke",
  "Resource": "arn:aws:execute-api:<REGION>:<TRUFFLE_ACCOUNT>:<API_ID>/prod/*"
}
```

Attach this to their IAM user/role, or add it as a permission in their IdC
permission set.

### 4. Run the Local UI in Managed Mode

```bash
cd frontend

TRUFFLE_MODE=managed \
TRUFFLE_API_ENDPOINT=https://abc123xyz.execute-api.us-east-1.amazonaws.com/prod \
TRUFFLE_API_REGION=us-east-1 \
python app.py
```

Or export the variables in your shell profile:

```bash
export TRUFFLE_MODE=managed
export TRUFFLE_API_ENDPOINT=https://abc123xyz.execute-api.us-east-1.amazonaws.com/prod
export TRUFFLE_API_REGION=us-east-1
# Optional: use a specific AWS profile for API signing
export TRUFFLE_API_PROFILE=truffle-user
```

Then just run `python app.py` as usual.

---

## Switching Back to Local Mode

Remove the environment variables or set:

```bash
export TRUFFLE_MODE=local
```

The UI reverts to running scans directly on your machine using your local
credentials. No backend infrastructure needed.

---

## Project Structure

```
managed solution/
├── bin/app.ts                         # CDK app entry point
├── lib/
│   ├── api-stack.ts                   # API Gateway (IAM auth, org resource policy)
│   ├── workflow-stack.ts              # Lambda functions + Step Functions
│   └── storage-stack.ts              # DynamoDB + S3
├── lambda/
│   ├── start-job/                     # Start Step Functions execution
│   ├── get-status/                    # Poll job progress
│   ├── get-result/                    # Fetch results from S3
│   ├── scan-unit/                     # Scan one account+region (async parallel)
│   ├── scan-global/                   # Scan global services (IAM, Orgs)
│   ├── discover-roles/                # IAM Federation role discovery
│   ├── migrate-role/                  # Trust policy migration (per role)
│   ├── aggregate/                     # Merge results, write to S3
│   └── shared/                        # Credential helpers, DynamoDB utils
├── layers/
│   └── custom-boto3/                  # Preview SDK Lambda Layer
│       ├── build.sh                   # Builds the layer from .whl files
│       └── .gitignore
├── state-machines/
│   ├── policy-scan.asl.json           # Policy scan workflow
│   ├── iam-discover.asl.json          # IAM discovery workflow
│   └── iam-migrate.asl.json           # Migration workflow
├── stackset-templates/
│   └── truffle-target-roles.yaml      # Cross-account TruffleRole
├── deploy.sh                          # One-command deployment script
├── package.json
├── tsconfig.json
├── cdk.json
├── ARCHITECTURE.md                    # Full architecture documentation
└── README.md                          # This file
```

---

## Tearing Down

```bash
npx cdk destroy --all
```

This removes all backend resources. Target account roles deployed via StackSet
must be removed separately:

```bash
aws cloudformation delete-stack-instances \
  --stack-set-name TruffleTargetRoles \
  --deployment-targets OrganizationalUnitIds=<YOUR_ROOT_OU_ID> \
  --regions us-east-1 \
  --no-retain-stacks

aws cloudformation delete-stack-set --stack-set-name TruffleTargetRoles
```

---

## Cost

With pay-per-request pricing across all components, the backend costs ~$3-4 per
full scan (1,000 accounts x 5 regions). See ARCHITECTURE.md for a detailed
breakdown.
