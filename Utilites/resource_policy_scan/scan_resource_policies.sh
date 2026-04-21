#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# scan_resource_policies.sh
#
# Assumes a read-only role in a target AWS account, then scans resource-based
# policies across a wide set of services for one or more search strings.
#
# Usage:
#   ./scan_resource_policies.sh \
#       --account-id 123456789012 \
#       --role-name ReadOnlyRole \
#       --search "string1,string2,string3" \
#       [--management-account] \
#       [--regions "us-east-1,us-west-2"]  # optional, defaults to all enabled regions
#
# Flags:
#   --account-id          Target AWS account ID
#   --role-name           Name of the read-only role to assume in the target account
#   --search              Comma-separated list of strings to search for in policies
#   --management-account  If set, also scan Organization SCPs and RCPs
#   --regions             Comma-separated list of regions (default: all enabled regions)
###############################################################################

# ─── Argument parsing ────────────────────────────────────────────────────────

ACCOUNT_ID=""
ROLE_NAME=""
SEARCH_STRINGS=""
MANAGEMENT_ACCOUNT=false
REGIONS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --account-id)          ACCOUNT_ID="$2";          shift 2 ;;
    --role-name)           ROLE_NAME="$2";            shift 2 ;;
    --search)              SEARCH_STRINGS="$2";       shift 2 ;;
    --management-account)  MANAGEMENT_ACCOUNT=true;   shift   ;;
    --regions)             REGIONS="$2";              shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$ACCOUNT_ID" || -z "$ROLE_NAME" || -z "$SEARCH_STRINGS" ]]; then
  echo "Error: --account-id, --role-name, and --search are required." >&2
  exit 1
fi

# Build an array of search strings
IFS=',' read -ra SEARCH_TERMS <<< "$SEARCH_STRINGS"

# ─── Assume role ─────────────────────────────────────────────────────────────

ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
echo "Assuming role: ${ROLE_ARN}"

CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "policy-scan-session" \
  --query 'Credentials' \
  --output json)

export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r '.SessionToken')

echo "Assumed role successfully. Caller identity:"
aws sts get-caller-identity

# ─── Resolve regions ─────────────────────────────────────────────────────────

if [[ -n "$REGIONS" ]]; then
  IFS=',' read -ra REGION_LIST <<< "$REGIONS"
else
  REGION_LIST=($(aws ec2 describe-regions --query 'Regions[].RegionName' --output text))
fi

echo "Scanning regions: ${REGION_LIST[*]}"
echo ""

# ─── Helpers ─────────────────────────────────────────────────────────────────

# Build a single grep pattern like "term1|term2|term3"
GREP_PATTERN=$(IFS='|'; echo "${SEARCH_TERMS[*]}")

# Check a policy document (passed via stdin) for any of the search strings.
# If matched, print the resource ARN.
check_policy() {
  local resource_arn="$1"
  local policy_doc
  policy_doc=$(cat)
  if [[ -z "$policy_doc" || "$policy_doc" == "null" || "$policy_doc" == "None" ]]; then
    return
  fi
  if echo "$policy_doc" | grep -qE "$GREP_PATTERN"; then
    echo "  MATCH: $resource_arn"
  fi
}

# Silently skip errors (e.g. resource has no policy)
safe() {
  "$@" 2>/dev/null || true
}


# ─── Global (non-regional) services ──────────────────────────────────────────

scan_global_services() {
  echo "=== S3 (Global bucket list, per-bucket policy) ==="
  for bucket in $(safe aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    safe aws s3api get-bucket-policy --bucket "$bucket" --output text | check_policy "arn:aws:s3:::${bucket}"
  done

  echo "=== S3 Tables ==="
  # S3 Tables are regional but table buckets are listed per-region; handled in regional scan

  echo "=== Organizations (SCPs + RCPs) ==="
  if [[ "$MANAGEMENT_ACCOUNT" == true ]]; then
    # Service Control Policies
    for policy_id in $(safe aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
      safe aws organizations describe-policy --policy-id "$policy_id" --query 'Policy.Content' --output text | check_policy "SCP:${policy_id}"
    done
    # Resource Control Policies
    for policy_id in $(safe aws organizations list-policies --filter RESOURCE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
      safe aws organizations describe-policy --policy-id "$policy_id" --query 'Policy.Content' --output text | check_policy "RCP:${policy_id}"
    done
  else
    echo "  (skipped — not management/delegated admin account)"
  fi

  echo "=== IAM (role trust policies — global) ==="
  for role in $(safe aws iam list-roles --query 'Roles[].RoleName' --output text); do
    safe aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json | check_policy "arn:aws:iam::${ACCOUNT_ID}:role/${role}"
  done

  echo "=== AWS Private CA ==="
  for ca_arn in $(safe aws acm-pca list-certificate-authorities --query 'CertificateAuthorities[].Arn' --output text); do
    safe aws acm-pca get-policy --resource-arn "$ca_arn" --output text | check_policy "$ca_arn"
  done

  echo "=== Serverless Application Repository (Global) ==="
  for app_arn in $(safe aws serverlessrepo list-applications --query 'Applications[].ApplicationId' --output text); do
    safe aws serverlessrepo get-application-policy --application-id "$app_arn" --query 'Statements' --output json | check_policy "$app_arn"
  done
}


# ─── Regional services ───────────────────────────────────────────────────────

scan_regional_services() {
  local region="$1"

  echo ""
  echo "######################################################################"
  echo "# Region: ${region}"
  echo "######################################################################"

  # --- API Gateway (REST API policies) ---
  echo "=== API Gateway ==="
  for api_id in $(safe aws apigateway get-rest-apis --region "$region" --query 'items[].id' --output text); do
    safe aws apigateway get-rest-api --rest-api-id "$api_id" --region "$region" --query 'policy' --output text | check_policy "arn:aws:apigateway:${region}::/restapis/${api_id}"
  done

  # --- AWS Backup (vault access policy) ---
  echo "=== Backup Vaults ==="
  for vault in $(safe aws backup list-backup-vaults --region "$region" --query 'BackupVaultList[].BackupVaultName' --output text); do
    safe aws backup get-backup-vault-access-policy --backup-vault-name "$vault" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:backup:${region}:${ACCOUNT_ID}:backup-vault:${vault}"
  done

  # --- Cloud9 (environment membership — no resource policy per se, skip or note) ---
  # Cloud9 doesn't expose a traditional resource policy via CLI; sharing is via membership.
  # Including a placeholder if future API support is added.

  # --- CloudTrail (Lake event data store, dashboard, channel resource policies) ---
  echo "=== CloudTrail (Event Data Stores) ==="
  for eds_arn in $(safe aws cloudtrail list-event-data-stores --region "$region" --query 'EventDataStores[].EventDataStoreArn' --output text); do
    safe aws cloudtrail get-resource-policy --resource-arn "$eds_arn" --region "$region" --query 'ResourcePolicy' --output text | check_policy "$eds_arn"
  done
  echo "=== CloudTrail (Channels) ==="
  for ch_arn in $(safe aws cloudtrail list-channels --region "$region" --query 'Channels[].ChannelArn' --output text); do
    safe aws cloudtrail get-resource-policy --resource-arn "$ch_arn" --region "$region" --query 'ResourcePolicy' --output text | check_policy "$ch_arn"
  done

  # --- CloudWatch Logs (log group resource policies) ---
  echo "=== CloudWatch Logs ==="
  safe aws logs describe-resource-policies --region "$region" --query 'resourcePolicies[]' --output json | jq -c '.[]' 2>/dev/null | while read -r rp; do
    name=$(echo "$rp" | jq -r '.policyName')
    echo "$rp" | jq -r '.policyDocument' | check_policy "logs-resource-policy:${region}:${name}"
  done

  # --- CodeArtifact (domain + repository policies) ---
  echo "=== CodeArtifact ==="
  for domain in $(safe aws codeartifact list-domains --region "$region" --query 'domains[].name' --output text); do
    safe aws codeartifact get-domain-permissions-policy --domain "$domain" --region "$region" --query 'policy.document' --output text | check_policy "codeartifact-domain:${region}:${domain}"
    for repo in $(safe aws codeartifact list-repositories-in-domain --domain "$domain" --region "$region" --query 'repositories[].name' --output text); do
      safe aws codeartifact get-repository-permissions-policy --domain "$domain" --repository "$repo" --region "$region" --query 'policy.document' --output text | check_policy "codeartifact-repo:${region}:${domain}/${repo}"
    done
  done

  # --- CodeBuild (project resource policies) ---
  echo "=== CodeBuild ==="
  for project in $(safe aws codebuild list-projects --region "$region" --query 'projects[]' --output text); do
    safe aws codebuild get-resource-policy --resource-arn "arn:aws:codebuild:${region}:${ACCOUNT_ID}:project/${project}" --region "$region" --query 'policy' --output text | check_policy "arn:aws:codebuild:${region}:${ACCOUNT_ID}:project/${project}"
  done

  # --- DynamoDB (table resource policies — newer feature) ---
  echo "=== DynamoDB ==="
  for table in $(safe aws dynamodb list-tables --region "$region" --query 'TableNames[]' --output text); do
    safe aws dynamodb get-resource-policy --resource-arn "arn:aws:dynamodb:${region}:${ACCOUNT_ID}:table/${table}" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:dynamodb:${region}:${ACCOUNT_ID}:table/${table}"
  done

  # --- Entity Resolution (policy) ---
  echo "=== Entity Resolution ==="
  for wf_arn in $(safe aws entityresolution list-matching-workflows --region "$region" --query 'workflowSummaries[].workflowArn' --output text); do
    safe aws entityresolution get-policy --arn "$wf_arn" --region "$region" --query 'policy' --output text | check_policy "$wf_arn"
  done
  for sm_arn in $(safe aws entityresolution list-schema-mappings --region "$region" --query 'schemaList[].schemaArn' --output text); do
    safe aws entityresolution get-policy --arn "$sm_arn" --region "$region" --query 'policy' --output text | check_policy "$sm_arn"
  done
  for id_ns_arn in $(safe aws entityresolution list-id-namespaces --region "$region" --query 'idNamespaceSummaries[].idNamespaceArn' --output text); do
    safe aws entityresolution get-policy --arn "$id_ns_arn" --region "$region" --query 'policy' --output text | check_policy "$id_ns_arn"
  done


  # --- EventBridge (event bus policies) ---
  echo "=== EventBridge ==="
  for bus in $(safe aws events list-event-buses --region "$region" --query 'EventBuses[].Name' --output text); do
    safe aws events describe-event-bus --name "$bus" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:events:${region}:${ACCOUNT_ID}:event-bus/${bus}"
  done

  # --- EventBridge Schemas (registry policies) ---
  echo "=== EventBridge Schemas ==="
  for registry in $(safe aws schemas list-registries --region "$region" --query 'Registries[].RegistryName' --output text); do
    safe aws schemas get-resource-policy --registry-name "$registry" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:schemas:${region}:${ACCOUNT_ID}:registry/${registry}"
  done

  # --- Glue (resource policies — partial, catalog-level) ---
  echo "=== Glue ==="
  safe aws glue get-resource-policy --region "$region" --query 'PolicyInJson' --output text | check_policy "glue-catalog-policy:${region}"
  # Glue also supports per-resource policies via get-resource-policies (plural)
  safe aws glue get-resource-policies --region "$region" --query 'GetResourcePoliciesResponseList[].PolicyInJson' --output json 2>/dev/null | jq -r '.[]' 2>/dev/null | while read -r pol; do
    echo "$pol" | check_policy "glue-resource-policy:${region}"
  done

  # --- KMS (key policies) ---
  echo "=== KMS ==="
  for key_id in $(safe aws kms list-keys --region "$region" --query 'Keys[].KeyId' --output text); do
    safe aws kms get-key-policy --key-id "$key_id" --policy-name default --region "$region" --output text | check_policy "arn:aws:kms:${region}:${ACCOUNT_ID}:key/${key_id}"
  done

  # --- Kinesis Data Streams (resource policy) ---
  echo "=== Kinesis Data Streams ==="
  for stream_arn in $(safe aws kinesis list-streams --region "$region" --query 'StreamSummaries[].StreamARN' --output text); do
    safe aws kinesis get-resource-policy --resource-arn "$stream_arn" --region "$region" --query 'Policy' --output text | check_policy "$stream_arn"
  done

  # --- Lambda (function policies) ---
  echo "=== Lambda ==="
  for func in $(safe aws lambda list-functions --region "$region" --query 'Functions[].FunctionName' --output text); do
    safe aws lambda get-policy --function-name "$func" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:lambda:${region}:${ACCOUNT_ID}:function:${func}"
  done
  # Lambda layer version policies
  for layer in $(safe aws lambda list-layers --region "$region" --query 'Layers[].LayerName' --output text); do
    for version in $(safe aws lambda list-layer-versions --layer-name "$layer" --region "$region" --query 'LayerVersions[].Version' --output text); do
      safe aws lambda get-layer-version-policy --layer-name "$layer" --version-number "$version" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:lambda:${region}:${ACCOUNT_ID}:layer:${layer}:${version}"
    done
  done

  # --- Lex V2 (bot resource policies) ---
  echo "=== Lex V2 ==="
  for bot_id in $(safe aws lexv2-models list-bots --region "$region" --query 'botSummaries[].botId' --output text); do
    safe aws lexv2-models describe-resource-policy --resource-arn "arn:aws:lex:${region}:${ACCOUNT_ID}:bot/${bot_id}" --region "$region" --query 'policy' --output text | check_policy "arn:aws:lex:${region}:${ACCOUNT_ID}:bot/${bot_id}"
  done

  # --- MediaStore (container policies) ---
  echo "=== MediaStore ==="
  for container in $(safe aws mediastore list-containers --region "$region" --query 'Containers[].ContainerName' --output text); do
    safe aws mediastore get-container-policy --container-name "$container" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:mediastore:${region}:${ACCOUNT_ID}:container/${container}"
  done

  # --- OpenSearch Service (domain access policies) ---
  echo "=== OpenSearch ==="
  for domain in $(safe aws opensearch list-domain-names --region "$region" --query 'DomainNames[].DomainName' --output text); do
    safe aws opensearch describe-domain --domain-name "$domain" --region "$region" --query 'DomainStatus.AccessPolicies' --output text | check_policy "arn:aws:es:${region}:${ACCOUNT_ID}:domain/${domain}"
  done


  # --- S3 Express (directory bucket policies) ---
  echo "=== S3 Express (Directory Buckets) ==="
  for bucket in $(safe aws s3api list-directory-buckets --region "$region" --query 'Buckets[].Name' --output text); do
    safe aws s3api get-bucket-policy --bucket "$bucket" --region "$region" --output text | check_policy "arn:aws:s3express:${region}:${ACCOUNT_ID}:bucket/${bucket}"
  done

  # --- S3 Glacier (vault access + lock policies) ---
  echo "=== S3 Glacier ==="
  for vault in $(safe aws glacier list-vaults --account-id "$ACCOUNT_ID" --region "$region" --query 'VaultList[].VaultName' --output text); do
    safe aws glacier get-vault-access-policy --account-id "$ACCOUNT_ID" --vault-name "$vault" --region "$region" --query 'policy.Policy' --output text | check_policy "arn:aws:glacier:${region}:${ACCOUNT_ID}:vaults/${vault}"
  done

  # --- S3 Tables (table bucket policies) ---
  echo "=== S3 Tables ==="
  for tb_arn in $(safe aws s3tables list-table-buckets --region "$region" --query 'tableBuckets[].arn' --output text); do
    safe aws s3tables get-table-bucket-policy --table-bucket-arn "$tb_arn" --region "$region" --query 'resourcePolicy' --output text | check_policy "$tb_arn"
  done

  # --- Secrets Manager (secret resource policies) ---
  echo "=== Secrets Manager ==="
  for secret_arn in $(safe aws secretsmanager list-secrets --region "$region" --query 'SecretList[].ARN' --output text); do
    safe aws secretsmanager get-resource-policy --secret-id "$secret_arn" --region "$region" --query 'ResourcePolicy' --output text | check_policy "$secret_arn"
  done

  # --- SES v2 (identity policies) ---
  echo "=== SES v2 ==="
  for identity in $(safe aws sesv2 list-email-identities --region "$region" --query 'EmailIdentities[].IdentityName' --output text); do
    for pol_name in $(safe aws ses list-identity-policies --identity "$identity" --region "$region" --query 'PolicyNames[]' --output text); do
      safe aws ses get-identity-policies --identity "$identity" --policy-names "$pol_name" --region "$region" --query "Policies.${pol_name}" --output text | check_policy "ses-identity:${region}:${identity}:${pol_name}"
    done
  done

  # --- SES Mail Manager (ingress point / rule set / traffic policy resource policies) ---
  echo "=== SES Mail Manager ==="
  for ip_id in $(safe aws sesv2 list-email-identities --region "$region" --query 'EmailIdentities[].IdentityName' --output text 2>/dev/null); do
    # Mail Manager is relatively new; resource policies accessed via mailmanager subcommands
    :
  done
  # Note: SES Mail Manager resource policies may require the mailmanager API which is
  # not yet fully available in all CLI versions. Placeholder for future expansion.

  # --- SNS (topic policies) ---
  echo "=== SNS ==="
  for topic_arn in $(safe aws sns list-topics --region "$region" --query 'Topics[].TopicArn' --output text); do
    safe aws sns get-topic-attributes --topic-arn "$topic_arn" --region "$region" --query 'Attributes.Policy' --output text | check_policy "$topic_arn"
  done

  # --- SQS (queue policies) ---
  echo "=== SQS ==="
  for queue_url in $(safe aws sqs list-queues --region "$region" --query 'QueueUrls[]' --output text); do
    safe aws sqs get-queue-attributes --queue-url "$queue_url" --attribute-names Policy --region "$region" --query 'Attributes.Policy' --output text | check_policy "sqs:${region}:${queue_url}"
  done

  # --- Systems Manager (SSM) — OpsItemGroup / document resource policies ---
  echo "=== Systems Manager ==="
  # SSM documents can have resource sharing policies
  for doc in $(safe aws ssm list-documents --region "$region" --document-filter-list "key=Owner,value=Self" --query 'DocumentIdentifiers[].Name' --output text); do
    safe aws ssm describe-document-permission --name "$doc" --permission-type Share --region "$region" --output json | check_policy "ssm-document:${region}:${doc}"
  done
  # SSM service settings / resource policies (partial)
  safe aws ssm get-resource-policies --resource-arn "arn:aws:ssm:${region}:${ACCOUNT_ID}:opsitemgroup/default" --region "$region" --query 'Policies[].Policy' --output json 2>/dev/null | jq -r '.[]' 2>/dev/null | while read -r pol; do
    echo "$pol" | check_policy "ssm-opsitemgroup:${region}:default"
  done

  # --- SSM Incident Manager (response plan policies) ---
  echo "=== SSM Incident Manager ==="
  for rp_arn in $(safe aws ssm-incidents list-response-plans --region "$region" --query 'responsePlanSummaries[].arn' --output text); do
    safe aws ssm-incidents get-resource-policies --resource-arn "$rp_arn" --region "$region" --query 'resourcePolicies[].policyDocument' --output json 2>/dev/null | jq -r '.[]' 2>/dev/null | while read -r pol; do
      echo "$pol" | check_policy "$rp_arn"
    done
  done

  # --- SSM Incident Manager Contacts (contact/escalation plan policies) ---
  echo "=== SSM Incident Manager Contacts ==="
  for contact_arn in $(safe aws ssm-contacts list-contacts --region "$region" --query 'Contacts[].ContactArn' --output text); do
    safe aws ssm-contacts get-contact-policy --contact-arn "$contact_arn" --region "$region" --query 'Policy' --output text | check_policy "$contact_arn"
  done


  # --- ECR (repository policies) ---
  echo "=== ECR ==="
  for repo in $(safe aws ecr describe-repositories --region "$region" --query 'repositories[].repositoryName' --output text); do
    safe aws ecr get-repository-policy --repository-name "$repo" --region "$region" --query 'policyText' --output text | check_policy "arn:aws:ecr:${region}:${ACCOUNT_ID}:repository/${repo}"
  done

  # --- EFS (file system policies) ---
  echo "=== EFS ==="
  for fs_id in $(safe aws efs describe-file-systems --region "$region" --query 'FileSystems[].FileSystemId' --output text); do
    safe aws efs describe-file-system-policy --file-system-id "$fs_id" --region "$region" --query 'Policy' --output text | check_policy "arn:aws:elasticfilesystem:${region}:${ACCOUNT_ID}:file-system/${fs_id}"
  done

  # --- Redshift Serverless (snapshot sharing — resource policies on workgroups/namespaces) ---
  echo "=== Redshift Serverless ==="
  for ns in $(safe aws redshift-serverless list-namespaces --region "$region" --query 'namespaces[].namespaceName' --output text); do
    for snap in $(safe aws redshift-serverless list-snapshots --namespace-name "$ns" --region "$region" --query 'snapshots[].snapshotName' --output text); do
      safe aws redshift-serverless get-resource-policy --resource-arn "arn:aws:redshift-serverless:${region}:${ACCOUNT_ID}:snapshot/${ns}/${snap}" --region "$region" --query 'resourcePolicy.policy' --output text | check_policy "redshift-serverless-snapshot:${region}:${ns}/${snap}"
    done
  done

  # --- Rekognition (Custom Labels project policies — for model copying) ---
  echo "=== Rekognition ==="
  for project_arn in $(safe aws rekognition describe-projects --region "$region" --query 'ProjectDescriptions[].ProjectArn' --output text); do
    safe aws rekognition list-project-policies --project-arn "$project_arn" --region "$region" --query 'ProjectPolicies[].PolicyDocument' --output json 2>/dev/null | jq -r '.[]' 2>/dev/null | while read -r pol; do
      echo "$pol" | check_policy "$project_arn"
    done
  done

  # --- VPC Endpoints (endpoint policies) ---
  echo "=== VPC Endpoints ==="
  for vpce_id in $(safe aws ec2 describe-vpc-endpoints --region "$region" --query 'VpcEndpoints[].VpcEndpointId' --output text); do
    safe aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$vpce_id" --region "$region" --query 'VpcEndpoints[0].PolicyDocument' --output text | check_policy "arn:aws:ec2:${region}:${ACCOUNT_ID}:vpc-endpoint/${vpce_id}"
  done
}

# ─── Main execution ──────────────────────────────────────────────────────────

echo ""
echo "======================================================================"
echo "Scanning for strings: ${SEARCH_TERMS[*]}"
echo "======================================================================"
echo ""

# Global services (run once)
scan_global_services

# Regional services (run per region)
for region in "${REGION_LIST[@]}"; do
  scan_regional_services "$region"
done

echo ""
echo "======================================================================"
echo "Scan complete."
echo "======================================================================"
