#!/usr/bin/env python3
"""
scan_resource_policies.py

Scans resource-based policies across a wide set of AWS services for one or
more search strings. Supports single-account (current credentials) or
multi-account (hub-and-spoke role assumption).

Usage:
    # Single account — use current credentials
    python scan_resource_policies.py --search "string1,string2"

    # Multi-account — assume a role in each target account
    python scan_resource_policies.py \
        --account-ids 111111111111,222222222222 \
        --role-name ReadOnlyRole \
        --search "string1,string2" \
        [--management-account] \
        [--regions us-east-1,us-west-2] \
        [--output scan_results.json]
"""

import argparse
import json

import boto3
from botocore.exceptions import ClientError, BotoCoreError


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_session_info() -> tuple[boto3.Session, str]:
    """Return the current session and resolve the account ID from it."""
    session = boto3.Session()
    identity = session.client("sts").get_caller_identity()
    account_id = identity["Account"]
    print(f"Using current credentials: {identity['Arn']}  (account {account_id})")
    return session, account_id


def assume_role(account_id: str, role_name: str) -> boto3.Session:
    """Assume a role in the target account and return a new session."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    print(f"Assuming role: {role_arn}")
    sts = boto3.client("sts")
    creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="policy-scan-session")["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    print(f"  Assumed into account {account_id}")
    return session


def get_regions(session: boto3.Session, regions_arg: str | None) -> list[str]:
    if regions_arg:
        return [r.strip() for r in regions_arg.split(",")]
    return [r["RegionName"] for r in session.client("ec2").describe_regions()["Regions"]]


def policy_text(obj) -> str:
    if obj is None:
        return ""
    if isinstance(obj, dict):
        return json.dumps(obj)
    return str(obj)


def check_policy(policy: str, resource_arn: str, service: str, search_terms: list[str]) -> dict | None:
    if not policy:
        return None
    matched = [t for t in search_terms if t in policy]
    if matched:
        return {"resource_arn": resource_arn, "service": service, "matched_terms": matched}
    return None


def safe(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ClientError, BotoCoreError):
        return None


def paginate(client, method: str, key: str, **kwargs) -> list:
    items = []
    try:
        for page in client.get_paginator(method).paginate(**kwargs):
            items.extend(page.get(key, []))
    except (ClientError, BotoCoreError):
        pass
    return items


def heading(title: str):
    print(f"=== {title} ===")


# ─── Global scanners ────────────────────────────────────────────────────────

def scan_s3(session, account_id, terms):
    heading("S3")
    matches = []
    s3 = session.client("s3")
    resp = safe(s3.list_buckets)
    for b in (resp or {}).get("Buckets", []):
        name = b["BucketName"]
        pol = safe(s3.get_bucket_policy, Bucket=name)
        if pol:
            hit = check_policy(policy_text(pol.get("Policy")), f"arn:aws:s3:::{name}", "S3", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_organizations(session, terms):
    heading("Organizations (SCPs + RCPs)")
    matches = []
    org = session.client("organizations")
    for ptype in ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"):
        label = "SCP" if "SERVICE" in ptype else "RCP"
        for p in paginate(org, "list_policies", "Policies", Filter=ptype):
            resp = safe(org.describe_policy, PolicyId=p["Id"])
            if resp:
                hit = check_policy(policy_text(resp["Policy"].get("Content")), f"{label}:{p['Id']}", "Organizations", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_iam_trust_policies(session, account_id, terms):
    heading("IAM (role trust policies)")
    matches = []
    for role in paginate(session.client("iam"), "list_roles", "Roles"):
        hit = check_policy(policy_text(role.get("AssumeRolePolicyDocument")),
                           f"arn:aws:iam::{account_id}:role/{role['RoleName']}", "IAM", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_private_ca(session, terms):
    heading("AWS Private CA")
    matches = []
    pca = session.client("acm-pca")
    for ca in paginate(pca, "list_certificate_authorities", "CertificateAuthorities"):
        resp = safe(pca.get_policy, ResourceArn=ca["Arn"])
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), ca["Arn"], "Private CA", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_serverless_repo(session, terms):
    heading("Serverless Application Repository")
    matches = []
    sar = session.client("serverlessrepo")
    for app in paginate(sar, "list_applications", "Applications"):
        resp = safe(sar.get_application_policy, ApplicationId=app["ApplicationId"])
        if resp:
            hit = check_policy(policy_text(resp.get("Statements")), app["ApplicationId"], "Serverless Application Repository", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_global_services(session, account_id, terms, management_account):
    matches = []
    matches.extend(scan_s3(session, account_id, terms))
    if management_account:
        matches.extend(scan_organizations(session, terms))
    else:
        heading("Organizations (SCPs + RCPs)")
        print("  (skipped — not management/delegated admin account)")
    matches.extend(scan_iam_trust_policies(session, account_id, terms))
    matches.extend(scan_private_ca(session, terms))
    matches.extend(scan_serverless_repo(session, terms))
    return matches


# ─── Regional scanners ──────────────────────────────────────────────────────

def scan_api_gateway(session, region, account_id, terms):
    heading("API Gateway")
    matches = []
    apigw = session.client("apigateway", region_name=region)
    for api in paginate(apigw, "get_rest_apis", "items"):
        hit = check_policy(policy_text(api.get("policy")),
                           f"arn:aws:apigateway:{region}::/restapis/{api['id']}", "API Gateway", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_backup(session, region, account_id, terms):
    heading("Backup Vaults")
    matches = []
    bk = session.client("backup", region_name=region)
    for v in paginate(bk, "list_backup_vaults", "BackupVaultList"):
        resp = safe(bk.get_backup_vault_access_policy, BackupVaultName=v["BackupVaultName"])
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:backup:{region}:{account_id}:backup-vault:{v['BackupVaultName']}", "Backup", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_cloudtrail(session, region, account_id, terms):
    heading("CloudTrail (Event Data Stores + Channels)")
    matches = []
    ct = session.client("cloudtrail", region_name=region)
    for src_key, list_key, arn_key in [
        ("list_event_data_stores", "EventDataStores", "EventDataStoreArn"),
        ("list_channels", "Channels", "ChannelArn"),
        ("list_dashboards", "Dashboards", "DashboardArn"),
    ]:
        resp = safe(getattr(ct, src_key))
        for item in (resp or {}).get(list_key, []):
            arn = item[arn_key]
            pol_resp = safe(ct.get_resource_policy, ResourceArn=arn)
            if pol_resp:
                hit = check_policy(policy_text(pol_resp.get("ResourcePolicy")), arn, "CloudTrail", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_cloudwatch_logs(session, region, account_id, terms):
    heading("CloudWatch Logs")
    matches = []
    logs = session.client("logs", region_name=region)
    resp = safe(logs.describe_resource_policies)
    for rp in (resp or {}).get("resourcePolicies", []):
        name = rp.get("policyName", "unknown")
        hit = check_policy(policy_text(rp.get("policyDocument")),
                           f"logs-resource-policy:{region}:{name}", "CloudWatch Logs", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_codeartifact(session, region, account_id, terms):
    heading("CodeArtifact")
    matches = []
    ca = session.client("codeartifact", region_name=region)
    for d in paginate(ca, "list_domains", "domains"):
        domain = d["name"]
        resp = safe(ca.get_domain_permissions_policy, domain=domain)
        if resp:
            hit = check_policy(policy_text(resp.get("policy", {}).get("document")),
                               f"codeartifact-domain:{region}:{domain}", "CodeArtifact", terms)
            if hit:
                matches.append(hit)
        for r in paginate(ca, "list_repositories_in_domain", "repositories", domain=domain):
            resp2 = safe(ca.get_repository_permissions_policy, domain=domain, repository=r["name"])
            if resp2:
                hit = check_policy(policy_text(resp2.get("policy", {}).get("document")),
                                   f"codeartifact-repo:{region}:{domain}/{r['name']}", "CodeArtifact", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_codebuild(session, region, account_id, terms):
    heading("CodeBuild")
    matches = []
    cb = session.client("codebuild", region_name=region)
    for project in paginate(cb, "list_projects", "projects"):
        arn = f"arn:aws:codebuild:{region}:{account_id}:project/{project}"
        resp = safe(cb.get_resource_policy, resourceArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("policy")), arn, "CodeBuild", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_dynamodb(session, region, account_id, terms):
    heading("DynamoDB")
    matches = []
    ddb = session.client("dynamodb", region_name=region)
    for table in paginate(ddb, "list_tables", "TableNames"):
        arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table}"
        resp = safe(ddb.get_resource_policy, ResourceArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "DynamoDB", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_entity_resolution(session, region, account_id, terms):
    heading("Entity Resolution")
    matches = []
    er = session.client("entityresolution", region_name=region)
    for list_method, key, arn_key in [
        ("list_matching_workflows", "workflowSummaries", "workflowArn"),
        ("list_schema_mappings", "schemaList", "schemaArn"),
        ("list_id_namespaces", "idNamespaceSummaries", "idNamespaceArn"),
    ]:
        for item in paginate(er, list_method, key):
            arn = item[arn_key]
            resp = safe(er.get_policy, arn=arn)
            if resp:
                hit = check_policy(policy_text(resp.get("policy")), arn, "Entity Resolution", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_eventbridge(session, region, account_id, terms):
    heading("EventBridge")
    matches = []
    eb = session.client("events", region_name=region)
    for bus in paginate(eb, "list_event_buses", "EventBuses"):
        name = bus["Name"]
        pol = policy_text(bus.get("Policy"))
        if not pol:
            resp = safe(eb.describe_event_bus, Name=name)
            if resp:
                pol = policy_text(resp.get("Policy"))
        hit = check_policy(pol, f"arn:aws:events:{region}:{account_id}:event-bus/{name}", "EventBridge", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_eventbridge_schemas(session, region, account_id, terms):
    heading("EventBridge Schemas")
    matches = []
    schemas = session.client("schemas", region_name=region)
    for reg in paginate(schemas, "list_registries", "Registries"):
        resp = safe(schemas.get_resource_policy, RegistryName=reg["RegistryName"])
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:schemas:{region}:{account_id}:registry/{reg['RegistryName']}",
                               "EventBridge Schemas", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_glue(session, region, account_id, terms):
    heading("Glue")
    matches = []
    glue = session.client("glue", region_name=region)
    resp = safe(glue.get_resource_policy)
    if resp:
        hit = check_policy(policy_text(resp.get("PolicyInJson")), f"glue-catalog-policy:{region}", "Glue", terms)
        if hit:
            matches.append(hit)
    resp2 = safe(glue.get_resource_policies)
    for rp in (resp2 or {}).get("GetResourcePoliciesResponseList", []):
        hit = check_policy(policy_text(rp.get("PolicyInJson")), f"glue-resource-policy:{region}", "Glue", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_kms(session, region, account_id, terms):
    heading("KMS")
    matches = []
    kms = session.client("kms", region_name=region)
    for k in paginate(kms, "list_keys", "Keys"):
        resp = safe(kms.get_key_policy, KeyId=k["KeyId"], PolicyName="default")
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:kms:{region}:{account_id}:key/{k['KeyId']}", "KMS", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_kinesis(session, region, account_id, terms):
    heading("Kinesis Data Streams")
    matches = []
    kinesis = session.client("kinesis", region_name=region)
    for s in paginate(kinesis, "list_streams", "StreamSummaries"):
        arn = s["StreamARN"]
        resp = safe(kinesis.get_resource_policy, ResourceARN=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "Kinesis", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_lambda(session, region, account_id, terms):
    heading("Lambda")
    matches = []
    lam = session.client("lambda", region_name=region)
    for fn in paginate(lam, "list_functions", "Functions"):
        name = fn["FunctionName"]
        resp = safe(lam.get_policy, FunctionName=name)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:lambda:{region}:{account_id}:function:{name}", "Lambda", terms)
            if hit:
                matches.append(hit)
    for layer in paginate(lam, "list_layers", "Layers"):
        ln = layer["LayerName"]
        for v in paginate(lam, "list_layer_versions", "LayerVersions", LayerName=ln):
            resp = safe(lam.get_layer_version_policy, LayerName=ln, VersionNumber=v["Version"])
            if resp:
                hit = check_policy(policy_text(resp.get("Policy")),
                                   f"arn:aws:lambda:{region}:{account_id}:layer:{ln}:{v['Version']}", "Lambda", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_lex(session, region, account_id, terms):
    heading("Lex V2")
    matches = []
    lex = session.client("lexv2-models", region_name=region)
    for bot in paginate(lex, "list_bots", "botSummaries"):
        arn = f"arn:aws:lex:{region}:{account_id}:bot/{bot['botId']}"
        resp = safe(lex.describe_resource_policy, resourceArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("policy")), arn, "Lex V2", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_mediastore(session, region, account_id, terms):
    heading("MediaStore")
    matches = []
    ms = session.client("mediastore", region_name=region)
    for c in paginate(ms, "list_containers", "Containers"):
        name = c["ContainerName"]
        resp = safe(ms.get_container_policy, ContainerName=name)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:mediastore:{region}:{account_id}:container/{name}", "MediaStore", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_opensearch(session, region, account_id, terms):
    heading("OpenSearch")
    matches = []
    os_client = session.client("opensearch", region_name=region)
    resp = safe(os_client.list_domain_names)
    for d in (resp or {}).get("DomainNames", []):
        name = d["DomainName"]
        desc = safe(os_client.describe_domain, DomainName=name)
        if desc:
            hit = check_policy(policy_text(desc.get("DomainStatus", {}).get("AccessPolicies")),
                               f"arn:aws:es:{region}:{account_id}:domain/{name}", "OpenSearch", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_s3_express(session, region, account_id, terms):
    heading("S3 Express (Directory Buckets)")
    matches = []
    s3 = session.client("s3", region_name=region)
    resp = safe(s3.list_directory_buckets)
    for b in (resp or {}).get("Buckets", []):
        name = b["BucketName"]
        pol = safe(s3.get_bucket_policy, Bucket=name)
        if pol:
            hit = check_policy(policy_text(pol.get("Policy")),
                               f"arn:aws:s3express:{region}:{account_id}:bucket/{name}", "S3 Express", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_glacier(session, region, account_id, terms):
    heading("S3 Glacier")
    matches = []
    glacier = session.client("glacier", region_name=region)
    for v in paginate(glacier, "list_vaults", "VaultList", accountId=account_id):
        name = v["VaultName"]
        resp = safe(glacier.get_vault_access_policy, accountId=account_id, vaultName=name)
        if resp:
            hit = check_policy(policy_text(resp.get("policy", {}).get("Policy")),
                               f"arn:aws:glacier:{region}:{account_id}:vaults/{name}", "Glacier", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_s3_tables(session, region, account_id, terms):
    heading("S3 Tables")
    matches = []
    s3t = session.client("s3tables", region_name=region)
    # Custom pagination — uses continuationToken instead of standard NextToken
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["continuationToken"] = token
        resp = safe(s3t.list_table_buckets, **kwargs)
        if not resp:
            break
        for tb in resp.get("tableBuckets", []):
            arn = tb["arn"]
            resp2 = safe(s3t.get_table_bucket_policy, tableBucketARN=arn)
            if resp2:
                hit = check_policy(policy_text(resp2.get("resourcePolicy")), arn, "S3 Tables", terms)
                if hit:
                    matches.append(hit)
        token = resp.get("continuationToken")
        if not token:
            break
    return matches


def scan_secrets_manager(session, region, account_id, terms):
    heading("Secrets Manager")
    matches = []
    sm = session.client("secretsmanager", region_name=region)
    for s in paginate(sm, "list_secrets", "SecretList"):
        arn = s["ARN"]
        resp = safe(sm.get_resource_policy, SecretId=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("ResourcePolicy")), arn, "Secrets Manager", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_ses(session, region, account_id, terms):
    heading("SES v2")
    matches = []
    sesv2 = session.client("sesv2", region_name=region)
    ses = session.client("ses", region_name=region)
    resp = safe(sesv2.list_email_identities)
    for ident in (resp or {}).get("EmailIdentities", []):
        name = ident["IdentityName"]
        pol_resp = safe(ses.list_identity_policies, Identity=name)
        for pol_name in (pol_resp or {}).get("PolicyNames", []):
            r = safe(ses.get_identity_policies, Identity=name, PolicyNames=[pol_name])
            if r:
                hit = check_policy(policy_text(r.get("Policies", {}).get(pol_name)),
                                   f"ses-identity:{region}:{name}:{pol_name}", "SES", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_sns(session, region, account_id, terms):
    heading("SNS")
    matches = []
    sns = session.client("sns", region_name=region)
    for t in paginate(sns, "list_topics", "Topics"):
        arn = t["TopicArn"]
        resp = safe(sns.get_topic_attributes, TopicArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Attributes", {}).get("Policy")), arn, "SNS", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_sqs(session, region, account_id, terms):
    heading("SQS")
    matches = []
    sqs = session.client("sqs", region_name=region)
    resp = safe(sqs.list_queues)
    for url in (resp or {}).get("QueueUrls", []):
        attr = safe(sqs.get_queue_attributes, QueueUrl=url, AttributeNames=["Policy", "QueueArn"])
        if attr:
            queue_arn = attr.get("Attributes", {}).get("QueueArn", url)
            hit = check_policy(policy_text(attr.get("Attributes", {}).get("Policy")), queue_arn, "SQS", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_ssm(session, region, account_id, terms):
    heading("Systems Manager")
    matches = []
    ssm = session.client("ssm", region_name=region)
    for doc in paginate(ssm, "list_documents", "DocumentIdentifiers",
                        Filters=[{"Key": "Owner", "Values": ["Self"]}]):
        resp = safe(ssm.describe_document_permission, Name=doc["Name"], PermissionType="Share")
        if resp:
            hit = check_policy(policy_text(resp), f"ssm-document:{region}:{doc['Name']}", "SSM", terms)
            if hit:
                matches.append(hit)
    arn = f"arn:aws:ssm:{region}:{account_id}:opsitemgroup/default"
    resp = safe(ssm.get_resource_policies, ResourceArn=arn)
    for p in (resp or {}).get("Policies", []):
        hit = check_policy(policy_text(p.get("Policy")), f"ssm-opsitemgroup:{region}:default", "SSM", terms)
        if hit:
            matches.append(hit)
    return matches


def scan_ssm_incidents(session, region, account_id, terms):
    heading("SSM Incident Manager")
    matches = []
    inc = session.client("ssm-incidents", region_name=region)
    for plan in paginate(inc, "list_response_plans", "responsePlanSummaries"):
        arn = plan["arn"]
        resp = safe(inc.get_resource_policies, resourceArn=arn)
        for rp in (resp or {}).get("resourcePolicies", []):
            hit = check_policy(policy_text(rp.get("policyDocument")), arn, "SSM Incident Manager", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_ssm_contacts(session, region, account_id, terms):
    heading("SSM Incident Manager Contacts")
    matches = []
    contacts = session.client("ssm-contacts", region_name=region)
    for c in paginate(contacts, "list_contacts", "Contacts"):
        arn = c["ContactArn"]
        resp = safe(contacts.get_contact_policy, ContactArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "SSM Contacts", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_ecr(session, region, account_id, terms):
    heading("ECR")
    matches = []
    ecr = session.client("ecr", region_name=region)
    for r in paginate(ecr, "describe_repositories", "repositories"):
        name = r["repositoryName"]
        resp = safe(ecr.get_repository_policy, repositoryName=name)
        if resp:
            hit = check_policy(policy_text(resp.get("policyText")),
                               f"arn:aws:ecr:{region}:{account_id}:repository/{name}", "ECR", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_efs(session, region, account_id, terms):
    heading("EFS")
    matches = []
    efs = session.client("efs", region_name=region)
    for fs in paginate(efs, "describe_file_systems", "FileSystems"):
        fs_id = fs["FileSystemId"]
        resp = safe(efs.describe_file_system_policy, FileSystemId=fs_id)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")),
                               f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{fs_id}", "EFS", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_redshift_serverless(session, region, account_id, terms):
    heading("Redshift Serverless")
    matches = []
    rs = session.client("redshift-serverless", region_name=region)
    for ns in paginate(rs, "list_namespaces", "namespaces"):
        ns_name = ns["namespaceName"]
        for snap in paginate(rs, "list_snapshots", "snapshots", namespaceName=ns_name):
            arn = f"arn:aws:redshift-serverless:{region}:{account_id}:snapshot/{ns_name}/{snap['snapshotName']}"
            resp = safe(rs.get_resource_policy, resourceArn=arn)
            if resp:
                hit = check_policy(policy_text(resp.get("resourcePolicy", {}).get("policy")),
                                   arn, "Redshift Serverless", terms)
                if hit:
                    matches.append(hit)
    return matches


def scan_rekognition(session, region, account_id, terms):
    heading("Rekognition")
    matches = []
    rek = session.client("rekognition", region_name=region)
    for proj in paginate(rek, "describe_projects", "ProjectDescriptions"):
        arn = proj["ProjectArn"]
        resp = safe(rek.list_project_policies, ProjectArn=arn)
        for pp in (resp or {}).get("ProjectPolicies", []):
            hit = check_policy(policy_text(pp.get("PolicyDocument")), arn, "Rekognition", terms)
            if hit:
                matches.append(hit)
    return matches


def scan_vpc_endpoints(session, region, account_id, terms):
    heading("VPC Endpoints")
    matches = []
    ec2 = session.client("ec2", region_name=region)
    for ep in paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        vpce_id = ep["VpcEndpointId"]
        hit = check_policy(policy_text(ep.get("PolicyDocument")),
                           f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint/{vpce_id}", "VPC Endpoints", terms)
        if hit:
            matches.append(hit)
    return matches


# ─── Regional orchestrator ──────────────────────────────────────────────────

REGIONAL_SCANNERS = [
    scan_api_gateway, scan_backup, scan_cloudtrail, scan_cloudwatch_logs,
    scan_codeartifact, scan_codebuild, scan_dynamodb, scan_entity_resolution,
    scan_eventbridge, scan_eventbridge_schemas, scan_glue, scan_kms,
    scan_kinesis, scan_lambda, scan_lex, scan_mediastore, scan_opensearch,
    scan_s3_express, scan_glacier, scan_s3_tables, scan_secrets_manager,
    scan_ses, scan_sns, scan_sqs, scan_ssm, scan_ssm_incidents,
    scan_ssm_contacts, scan_ecr, scan_efs, scan_redshift_serverless,
    scan_rekognition, scan_vpc_endpoints,
]


def scan_regional_services(session, region, account_id, terms):
    print(f"\n{'#' * 70}")
    print(f"# Region: {region}")
    print(f"{'#' * 70}")
    matches = []
    for scanner in REGIONAL_SCANNERS:
        matches.extend(scanner(session, region, account_id, terms))
    return matches


# ─── Main ────────────────────────────────────────────────────────────────────

def scan_account(session, account_id, terms, regions_arg, management_account):
    """Run all scanners for a single account. Returns list of match dicts."""
    regions = get_regions(session, regions_arg)
    print(f"\n  Scanning regions: {', '.join(regions)}")

    matches = []
    matches.extend(scan_global_services(session, account_id, terms, management_account))
    for region in regions:
        matches.extend(scan_regional_services(session, region, account_id, terms))

    # Tag each match with the account ID
    for m in matches:
        m["account_id"] = account_id

    print(f"\n  Account {account_id}: {len(matches)} match(es)")
    return matches, regions


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scan AWS resource policies for search strings.")
    parser.add_argument("--search", required=True, help="Comma-separated list of strings to search for")
    parser.add_argument("--account-ids", default=None,
                        help="Comma-separated AWS account IDs to scan (requires --role-name)")
    parser.add_argument("--role-name", default=None,
                        help="Role name to assume in each target account")
    parser.add_argument("--management-account", action="store_true", help="Also scan Organization SCPs and RCPs")
    parser.add_argument("--regions", default=None, help="Comma-separated regions (default: all enabled)")
    parser.add_argument("--output", default="scan_results.json", help="Output file path (default: scan_results.json)")
    args = parser.parse_args()

    # Validate: if one of account-ids / role-name is set, both must be
    if bool(args.account_ids) != bool(args.role_name):
        parser.error("--account-ids and --role-name must be used together")

    terms = [t.strip() for t in args.search.split(",")]
    print(f"Search strings: {terms}")
    print("=" * 70)

    all_matches = []
    all_regions = set()

    if args.account_ids:
        # Multi-account mode: assume role in each account
        account_ids = [a.strip() for a in args.account_ids.split(",")]
        print(f"Multi-account mode: {len(account_ids)} account(s)")
        for acct in account_ids:
            session = assume_role(acct, args.role_name)
            matches, regions = scan_account(session, acct, terms, args.regions, args.management_account)
            all_matches.extend(matches)
            all_regions.update(regions)
    else:
        # Single-account mode: use current credentials
        session, account_id = get_session_info()
        matches, regions = scan_account(session, account_id, terms, args.regions, args.management_account)
        all_matches.extend(matches)
        all_regions.update(regions)

    # Summary
    print("\n" + "=" * 70)
    print(f"Scan complete. {len(all_matches)} resource(s) matched.")
    print("=" * 70)

    output = {
        "search_terms": terms,
        "regions_scanned": sorted(all_regions),
        "total_matches": len(all_matches),
        "matches": all_matches,
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results written to {args.output}")


if __name__ == "__main__":
    main()
