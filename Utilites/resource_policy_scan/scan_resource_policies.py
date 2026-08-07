#!/usr/bin/env python3
"""
scan_resource_policies.py

Scans resource-based policies across a wide set of AWS services for one or
more search strings. Supports single-account (current credentials) or
multi-account (hub-and-spoke role assumption).

Usage:
    # Single account — use current credentials
    python3 scan_resource_policies.py --search "string1,string2"

    # Multi-account — assume a role in each target account
    python3 scan_resource_policies.py \\
        --account-ids 111111111111,222222222222 \\
        --role-name ReadOnlyRole \\
        --search "string1,string2" \\
        [--management-account] \\
        [--regions us-east-1,us-west-2] \\
        [--services "S3,Lambda,KMS"] \\
        [--exclude-services "Rekognition,Lex V2"] \\
        [--workers 10] \\
        [--output scan_results.json]

    # List available service names for --services / --exclude-services
    python3 scan_resource_policies.py --list-services

Options:
    --search              Comma-separated list of strings to search for (required)
    --account-ids         Comma-separated AWS account IDs to scan (requires --role-name)
    --role-name           Role name to assume in each target account
    --management-account  Also scan Organization SCPs and RCPs
    --regions             Comma-separated regions (default: all enabled)
    --services            Comma-separated services to scan (default: all)
    --exclude-services    Comma-separated services to skip
    --list-services       Print available service names and exit
    --workers             Max parallel threads per service (default: 5)
    --output              Output file path (default: scan_results.json)
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.exceptions import ClientError, BotoCoreError


# ─── Constants ───────────────────────────────────────────────────────────────

MAX_WORKERS = 5  # Default concurrency; overridden by --workers CLI arg


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_session_info() -> tuple[boto3.Session, str]:
    """Return the current session and resolve the account ID from it."""
    session = boto3.Session()
    # Ensure the session has a region. If none is configured (no AWS_DEFAULT_REGION,
    # no profile region), default to us-east-1 so global service calls work.
    if not session.region_name:
        session = boto3.Session(region_name="us-east-1")
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


def _term_matches(term: str, policy: str) -> bool:
    """Check if a search term matches within the policy text.

    Supports IAM-style wildcards (* and ?) for pattern matching.
    All matching is case-insensitive.
    """
    if '*' in term or '?' in term:
        # Convert IAM-style wildcards to regex manually (fnmatch doesn't handle
        # ARN characters well). Escape everything except * and ?, then convert.
        parts = re.split(r'(\*|\?)', term)
        regex_parts = []
        for part in parts:
            if part == '*':
                regex_parts.append('.*')
            elif part == '?':
                regex_parts.append('.')
            else:
                regex_parts.append(re.escape(part))
        pattern = ''.join(regex_parts)
        return bool(re.search(pattern, policy, re.IGNORECASE))
    return term.lower() in policy.lower()


def check_policy(policy: str, resource_arn: str, service: str, search_terms: list[str], account_id: str = "") -> dict | None:
    count_resource()
    if not policy:
        return None
    matched = [t for t in search_terms if _term_matches(t, policy)]
    if matched:
        # Try to include the policy as parsed JSON; fall back to raw string
        try:
            policy_obj = json.loads(policy)
        except (json.JSONDecodeError, TypeError):
            policy_obj = policy
        return {"resource_arn": resource_arn, "service": service, "matched_terms": matched, "policy": policy_obj, "account_id": account_id}
    return None


def safe(fn, *args, _resource_arn: str = "", _service: str = "", **kwargs):
    try:
        return fn(*args, **kwargs)
    except (ClientError, BotoCoreError) as exc:
        if _resource_arn or _service:
            record_skip(_resource_arn or "unknown", _service or "unknown", exc)
        return None


def paginate(client, method: str, key: str, _service: str = "", **kwargs) -> list:
    items = []
    try:
        for page in client.get_paginator(method).paginate(**kwargs):
            items.extend(page.get(key, []))
    except (ClientError, BotoCoreError) as exc:
        record_skip(f"{method}(paginate)", _service or method, exc)
    return items


def parallel_check(items, fetch_fn, arn_fn, service, terms, account_id=""):
    """
    Fetch policies for a list of resources in parallel and check each one.

    Args:
        items: List of resources to check.
        fetch_fn: Callable(item) -> policy string or None.
        arn_fn: Callable(item) -> resource ARN string.
        service: Service name for match results.
        terms: Search terms list.
        account_id: Account ID to include in match results.

    Returns:
        List of match dicts.
    """
    matches = []

    def _process(item):
        arn = arn_fn(item)
        try:
            pol = fetch_fn(item)
        except (ClientError, BotoCoreError) as exc:
            record_skip(arn, service, exc)
            return None
        return check_policy(policy_text(pol), arn, service, terms, account_id)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_process, item): item for item in items}
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                matches.append(hit)
    return matches


def heading(title: str):
    """Legacy heading — now a no-op; progress is shown by the orchestrator."""
    pass


# ─── Progress tracking ──────────────────────────────────────────────────────

_resource_count = 0
_progress_state = {"current": 0, "total": 0, "label": "", "matches": 0}


# ─── Skipped resource tracking ──────────────────────────────────────────────

_skipped_resources: list[dict] = []


def record_skip(resource_arn: str, service: str, exc: Exception) -> None:
    """Record a resource that could not be scanned due to an error."""
    error_code = "Unknown"
    if hasattr(exc, "response"):
        try:
            error_code = exc.response["Error"]["Code"]
        except (KeyError, TypeError):
            error_code = type(exc).__name__
    else:
        error_code = type(exc).__name__

    _skipped_resources.append({
        "resource_arn": resource_arn,
        "service": service,
        "error_code": error_code,
        "error_message": str(exc),
    })


def get_skipped_resources() -> list[dict]:
    """Return the list of resources that were skipped due to errors."""
    return list(_skipped_resources)


def reset_skipped_resources() -> None:
    """Clear the skipped resources list (call at start of a new scan)."""
    _skipped_resources.clear()


def count_resource(n: int = 1):
    """Increment the global resource counter and refresh the progress line."""
    global _resource_count
    _resource_count += n
    _refresh_progress()


def _refresh_progress():
    """Redraw the progress line with current state."""
    s = _progress_state
    if s["total"] == 0:
        return
    bar_len = 20
    filled = int(bar_len * s["current"] / s["total"])
    bar = "█" * filled + "░" * (bar_len - filled)
    match_str = f"  ({s['matches']} match{'es' if s['matches'] != 1 else ''})" if s["matches"] else ""
    line = f"  [{bar}] {s['current']}/{s['total']} {s['label']} | {_resource_count} resources{match_str}"
    # Pad with spaces to overwrite any leftover characters from the previous line
    sys.stdout.write(f"\r{line:<79}")
    sys.stdout.flush()


def progress(current: int, total: int, label: str, matches_so_far: int):
    """Update progress state and redraw."""
    _progress_state.update(current=current, total=total, label=label, matches=matches_so_far)
    _refresh_progress()


def progress_done(total: int, matches_so_far: int):
    """Finish the progress line."""
    bar = "█" * 20
    match_str = f"  ({matches_so_far} match{'es' if matches_so_far != 1 else ''})" if matches_so_far else "  (no matches)"
    line = f"  [{bar}] {total}/{total} Done | {_resource_count} resources{match_str}"
    sys.stdout.write(f"\r{line:<79}\n")
    sys.stdout.flush()


# ─── Global scanners ────────────────────────────────────────────────────────

def scan_s3(session, account_id, terms):
    heading("S3")
    s3 = session.client("s3")
    resp = safe(s3.list_buckets)
    buckets = (resp or {}).get("Buckets", [])
    return parallel_check(
        buckets,
        fetch_fn=lambda b: (safe(s3.get_bucket_policy, Bucket=b["Name"]) or {}).get("Policy"),
        arn_fn=lambda b: f"arn:aws:s3:::{b['Name']}",
        service="S3",
        terms=terms, account_id=account_id,
    )


def scan_organizations(session, account_id, terms):
    heading("Organizations (SCPs + RCPs)")
    matches = []
    org = session.client("organizations")

    # Resolve org ID for proper ARN construction
    org_id = "o-unknown"
    try:
        org_id = org.describe_organization()["Organization"]["Id"]
    except Exception:
        pass

    for ptype in ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"):
        policy_type_path = "service_control_policy" if "SERVICE" in ptype else "resource_control_policy"
        for p in paginate(org, "list_policies", "Policies", Filter=ptype):
            resp = safe(org.describe_policy, PolicyId=p["Id"])
            if resp:
                full_arn = f"arn:aws:organizations::{account_id}:policy/{org_id}/{policy_type_path}/{p['Id']}"
                hit = check_policy(policy_text(resp["Policy"].get("Content")), full_arn, "Organizations", terms, account_id)
                if hit:
                    matches.append(hit)
    return matches


def scan_iam_trust_policies(session, account_id, terms):
    heading("IAM (role trust policies)")
    roles = paginate(session.client("iam"), "list_roles", "Roles")
    return parallel_check(
        roles,
        fetch_fn=lambda role: role.get("AssumeRolePolicyDocument"),
        arn_fn=lambda role: f"arn:aws:iam::{account_id}:role/{role['RoleName']}",
        service="IAM",
        terms=terms, account_id=account_id,
    )


def scan_private_ca(session, terms):
    heading("AWS Private CA")
    pca = session.client("acm-pca")
    cas = paginate(pca, "list_certificate_authorities", "CertificateAuthorities")
    return parallel_check(
        cas,
        fetch_fn=lambda ca: (safe(pca.get_policy, ResourceArn=ca["Arn"]) or {}).get("Policy"),
        arn_fn=lambda ca: ca["Arn"],
        service="Private CA",
        terms=terms,
    )


def scan_serverless_repo(session, terms):
    heading("Serverless Application Repository")
    sar = session.client("serverlessrepo")
    apps = paginate(sar, "list_applications", "Applications")
    return parallel_check(
        apps,
        fetch_fn=lambda app: (safe(sar.get_application_policy, ApplicationId=app["ApplicationId"]) or {}).get("Statements"),
        arn_fn=lambda app: app["ApplicationId"],
        service="Serverless Application Repository",
        terms=terms,
    )


GLOBAL_SCANNERS = [
    ("S3", scan_s3),
    ("Organizations (SCPs + RCPs)", scan_organizations),
    ("IAM (role trust policies)", scan_iam_trust_policies),
    ("AWS Private CA", scan_private_ca),
    ("Serverless Application Repository", scan_serverless_repo),
]


def _filter_scanners(scanners, service_filter, exclude_filter):
    """Filter a list of (name, fn) tuples based on include/exclude sets."""
    if service_filter:
        scanners = [(name, fn) for name, fn in scanners if name.lower() in service_filter]
    if exclude_filter:
        scanners = [(name, fn) for name, fn in scanners if name.lower() not in exclude_filter]
    return scanners


def scan_global_services(session, account_id, terms, management_account,
                         service_filter=None, exclude_filter=None):
    print("\n  Global services:")
    matches = []
    scanners = list(GLOBAL_SCANNERS)

    # Replace Organizations with a skip if not management account
    if not management_account:
        scanners = [(name, fn) for name, fn in scanners if fn != scan_organizations]

    scanners = _filter_scanners(scanners, service_filter, exclude_filter)

    total = len(scanners)
    for i, (name, scanner) in enumerate(scanners, 1):
        progress(i, total, name, len(matches))
        # Global scanners have varying signatures
        if scanner == scan_s3:
            matches.extend(scanner(session, account_id, terms))
        elif scanner == scan_iam_trust_policies:
            matches.extend(scanner(session, account_id, terms))
        elif scanner == scan_organizations:
            matches.extend(scanner(session, account_id, terms))
        elif scanner == scan_private_ca:
            matches.extend(scanner(session, terms))
        elif scanner == scan_serverless_repo:
            matches.extend(scanner(session, terms))
        else:
            matches.extend(scanner(session, account_id, terms))
    progress_done(total, len(matches))

    if not management_account:
        print("  (Organizations skipped — not management/delegated admin account)")

    return matches


# ─── Regional scanners ──────────────────────────────────────────────────────

def scan_api_gateway(session, region, account_id, terms):
    heading("API Gateway")
    apigw = session.client("apigateway", region_name=region)
    apis = paginate(apigw, "get_rest_apis", "items")
    return parallel_check(
        apis,
        fetch_fn=lambda api: api.get("policy"),
        arn_fn=lambda api: f"arn:aws:apigateway:{region}::/restapis/{api['id']}",
        service="API Gateway",
        terms=terms, account_id=account_id,
    )


def scan_backup(session, region, account_id, terms):
    heading("Backup Vaults")
    bk = session.client("backup", region_name=region)
    vaults = paginate(bk, "list_backup_vaults", "BackupVaultList")
    return parallel_check(
        vaults,
        fetch_fn=lambda v: (safe(bk.get_backup_vault_access_policy, BackupVaultName=v["BackupVaultName"]) or {}).get("Policy"),
        arn_fn=lambda v: f"arn:aws:backup:{region}:{account_id}:backup-vault:{v['BackupVaultName']}",
        service="Backup",
        terms=terms, account_id=account_id,
    )


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
    cb = session.client("codebuild", region_name=region)
    projects = paginate(cb, "list_projects", "projects")
    return parallel_check(
        projects,
        fetch_fn=lambda p: (safe(cb.get_resource_policy, resourceArn=f"arn:aws:codebuild:{region}:{account_id}:project/{p}") or {}).get("policy"),
        arn_fn=lambda p: f"arn:aws:codebuild:{region}:{account_id}:project/{p}",
        service="CodeBuild",
        terms=terms, account_id=account_id,
    )


def scan_dynamodb(session, region, account_id, terms):
    heading("DynamoDB")
    ddb = session.client("dynamodb", region_name=region)
    tables = paginate(ddb, "list_tables", "TableNames")
    return parallel_check(
        tables,
        fetch_fn=lambda t: (safe(ddb.get_resource_policy, ResourceArn=f"arn:aws:dynamodb:{region}:{account_id}:table/{t}") or {}).get("Policy"),
        arn_fn=lambda t: f"arn:aws:dynamodb:{region}:{account_id}:table/{t}",
        service="DynamoDB",
        terms=terms, account_id=account_id,
    )


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
    schemas = session.client("schemas", region_name=region)
    registries = paginate(schemas, "list_registries", "Registries")
    return parallel_check(
        registries,
        fetch_fn=lambda reg: (safe(schemas.get_resource_policy, RegistryName=reg["RegistryName"]) or {}).get("Policy"),
        arn_fn=lambda reg: f"arn:aws:schemas:{region}:{account_id}:registry/{reg['RegistryName']}",
        service="EventBridge Schemas",
        terms=terms, account_id=account_id,
    )


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
    kms = session.client("kms", region_name=region)
    keys = paginate(kms, "list_keys", "Keys")
    return parallel_check(
        keys,
        fetch_fn=lambda k: (safe(kms.get_key_policy, KeyId=k["KeyId"], PolicyName="default") or {}).get("Policy"),
        arn_fn=lambda k: f"arn:aws:kms:{region}:{account_id}:key/{k['KeyId']}",
        service="KMS",
        terms=terms, account_id=account_id,
    )


def scan_kinesis(session, region, account_id, terms):
    heading("Kinesis Data Streams")
    kinesis = session.client("kinesis", region_name=region)
    streams = paginate(kinesis, "list_streams", "StreamSummaries")
    return parallel_check(
        streams,
        fetch_fn=lambda s: (safe(kinesis.get_resource_policy, ResourceARN=s["StreamARN"]) or {}).get("Policy"),
        arn_fn=lambda s: s["StreamARN"],
        service="Kinesis",
        terms=terms, account_id=account_id,
    )


def scan_lambda(session, region, account_id, terms):
    heading("Lambda")
    lam = session.client("lambda", region_name=region)
    functions = paginate(lam, "list_functions", "Functions")
    matches = parallel_check(
        functions,
        fetch_fn=lambda fn: (safe(lam.get_policy, FunctionName=fn["FunctionName"]) or {}).get("Policy"),
        arn_fn=lambda fn: f"arn:aws:lambda:{region}:{account_id}:function:{fn['FunctionName']}",
        service="Lambda",
        terms=terms, account_id=account_id,
    )
    # Also check layer version policies
    layers = paginate(lam, "list_layers", "Layers")
    layer_versions = []
    for layer in layers:
        ln = layer["LayerName"]
        for v in paginate(lam, "list_layer_versions", "LayerVersions", LayerName=ln):
            layer_versions.append((ln, v["Version"]))
    matches.extend(parallel_check(
        layer_versions,
        fetch_fn=lambda lv: (safe(lam.get_layer_version_policy, LayerName=lv[0], VersionNumber=lv[1]) or {}).get("Policy"),
        arn_fn=lambda lv: f"arn:aws:lambda:{region}:{account_id}:layer:{lv[0]}:{lv[1]}",
        service="Lambda",
        terms=terms, account_id=account_id,
    ))
    return matches


def scan_lex(session, region, account_id, terms):
    heading("Lex V2")
    lex = session.client("lexv2-models", region_name=region)
    bots = paginate(lex, "list_bots", "botSummaries")
    return parallel_check(
        bots,
        fetch_fn=lambda bot: (safe(lex.describe_resource_policy, resourceArn=f"arn:aws:lex:{region}:{account_id}:bot/{bot['botId']}") or {}).get("policy"),
        arn_fn=lambda bot: f"arn:aws:lex:{region}:{account_id}:bot/{bot['botId']}",
        service="Lex V2",
        terms=terms, account_id=account_id,
    )


def scan_opensearch(session, region, account_id, terms):
    heading("OpenSearch")
    os_client = session.client("opensearch", region_name=region)
    resp = safe(os_client.list_domain_names)
    domains = (resp or {}).get("DomainNames", [])
    return parallel_check(
        domains,
        fetch_fn=lambda d: (safe(os_client.describe_domain, DomainName=d["DomainName"]) or {}).get("DomainStatus", {}).get("AccessPolicies"),
        arn_fn=lambda d: f"arn:aws:es:{region}:{account_id}:domain/{d['DomainName']}",
        service="OpenSearch",
        terms=terms, account_id=account_id,
    )


def scan_opensearch_serverless(session, region, account_id, terms):
    heading("OpenSearch Serverless (Data Access Policies)")
    matches = []
    aoss = session.client("opensearchserverless", region_name=region)
    # List all data access policies
    token = None
    while True:
        kwargs = {"type": "data"}
        if token:
            kwargs["nextToken"] = token
        resp = safe(aoss.list_access_policies, **kwargs)
        if not resp:
            break
        for summary in resp.get("accessPolicySummaries", []):
            name = summary["name"]
            detail = safe(aoss.get_access_policy, type="data", name=name)
            if detail:
                pol = policy_text(detail.get("accessPolicyDetail", {}).get("policy"))
                hit = check_policy(pol, f"aoss-data-access-policy:{region}:{name}",
                                   "OpenSearch Serverless", terms)
                if hit:
                    matches.append(hit)
        token = resp.get("nextToken")
        if not token:
            break
    return matches


def scan_s3_express(session, region, account_id, terms):
    heading("S3 Express (Directory Buckets)")
    s3 = session.client("s3", region_name=region)
    resp = safe(s3.list_directory_buckets)
    buckets = (resp or {}).get("Buckets", [])
    return parallel_check(
        buckets,
        fetch_fn=lambda b: (safe(s3.get_bucket_policy, Bucket=b["Name"]) or {}).get("Policy"),
        arn_fn=lambda b: f"arn:aws:s3express:{region}:{account_id}:bucket/{b['Name']}",
        service="S3 Express",
        terms=terms, account_id=account_id,
    )


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
    sm = session.client("secretsmanager", region_name=region)
    secrets = paginate(sm, "list_secrets", "SecretList")
    return parallel_check(
        secrets,
        fetch_fn=lambda s: (safe(sm.get_resource_policy, SecretId=s["ARN"]) or {}).get("ResourcePolicy"),
        arn_fn=lambda s: s["ARN"],
        service="Secrets Manager",
        terms=terms, account_id=account_id,
    )


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
    sns = session.client("sns", region_name=region)
    topics = paginate(sns, "list_topics", "Topics")
    return parallel_check(
        topics,
        fetch_fn=lambda t: (safe(sns.get_topic_attributes, TopicArn=t["TopicArn"]) or {}).get("Attributes", {}).get("Policy"),
        arn_fn=lambda t: t["TopicArn"],
        service="SNS",
        terms=terms, account_id=account_id,
    )


def scan_sqs(session, region, account_id, terms):
    heading("SQS")
    sqs = session.client("sqs", region_name=region)
    resp = safe(sqs.list_queues)
    urls = (resp or {}).get("QueueUrls", [])
    matches = []

    def _process(url):
        attr = safe(sqs.get_queue_attributes, QueueUrl=url, AttributeNames=["Policy", "QueueArn"])
        if attr:
            queue_arn = attr.get("Attributes", {}).get("QueueArn", url)
            return check_policy(policy_text(attr.get("Attributes", {}).get("Policy")), queue_arn, "SQS", terms)
        count_resource()
        return None

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(_process, url) for url in urls]
        for future in as_completed(futures):
            hit = future.result()
            if hit:
                matches.append(hit)
    return matches


def scan_ecr(session, region, account_id, terms):
    heading("ECR")
    ecr = session.client("ecr", region_name=region)
    repos = paginate(ecr, "describe_repositories", "repositories")
    return parallel_check(
        repos,
        fetch_fn=lambda r: (safe(ecr.get_repository_policy, repositoryName=r["repositoryName"]) or {}).get("policyText"),
        arn_fn=lambda r: f"arn:aws:ecr:{region}:{account_id}:repository/{r['repositoryName']}",
        service="ECR",
        terms=terms, account_id=account_id,
    )


def scan_efs(session, region, account_id, terms):
    heading("EFS")
    efs = session.client("efs", region_name=region)
    filesystems = paginate(efs, "describe_file_systems", "FileSystems")
    return parallel_check(
        filesystems,
        fetch_fn=lambda fs: (safe(efs.describe_file_system_policy, FileSystemId=fs["FileSystemId"]) or {}).get("Policy"),
        arn_fn=lambda fs: f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{fs['FileSystemId']}",
        service="EFS",
        terms=terms, account_id=account_id,
    )


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
    ec2 = session.client("ec2", region_name=region)
    endpoints = paginate(ec2, "describe_vpc_endpoints", "VpcEndpoints")
    return parallel_check(
        endpoints,
        fetch_fn=lambda ep: ep.get("PolicyDocument"),
        arn_fn=lambda ep: f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint/{ep['VpcEndpointId']}",
        service="VPC Endpoints",
        terms=terms, account_id=account_id,
    )


def scan_msk(session, region, account_id, terms):
    heading("MSK (Cluster Policies)")
    matches = []
    kafka = session.client("kafka", region_name=region)
    clusters = paginate(kafka, "list_clusters_v2", "ClusterInfoList")
    for cluster in clusters:
        arn = cluster.get("ClusterArn", "")
        resp = safe(kafka.get_cluster_policy, ClusterArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "MSK", terms, account_id)
            if hit:
                matches.append(hit)
    return matches


def scan_signer(session, region, account_id, terms):
    heading("Signer (Signing Profile Permissions)")
    matches = []
    signer = session.client("signer", region_name=region)
    profiles = paginate(signer, "list_signing_profiles", "profiles")
    for profile in profiles:
        profile_name = profile.get("profileName", "")
        arn = profile.get("arn", f"arn:aws:signer:{region}:{account_id}:/signing-profiles/{profile_name}")
        resp = safe(signer.list_profile_permissions, profileName=profile_name)
        if resp and resp.get("permissions"):
            # Serialize the permissions array to JSON for search
            pol = json.dumps(resp["permissions"])
            hit = check_policy(pol, arn, "Signer", terms, account_id)
            if hit:
                matches.append(hit)
    return matches


def scan_vpc_lattice(session, region, account_id, terms):
    heading("VPC Lattice (Auth Policies)")
    matches = []
    lattice = session.client("vpc-lattice", region_name=region)
    # Scan auth policies on services
    services = paginate(lattice, "list_services", "items")
    for svc in services:
        arn = svc.get("arn", "")
        resp = safe(lattice.get_auth_policy, resourceIdentifier=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("policy")), arn, "VPC Lattice", terms, account_id)
            if hit:
                matches.append(hit)
    # Scan auth policies on service networks
    networks = paginate(lattice, "list_service_networks", "items")
    for net in networks:
        arn = net.get("arn", "")
        resp = safe(lattice.get_auth_policy, resourceIdentifier=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("policy")), arn, "VPC Lattice", terms, account_id)
            if hit:
                matches.append(hit)
    return matches


def scan_network_firewall(session, region, account_id, terms):
    heading("Network Firewall (Resource Policies)")
    matches = []
    nfw = session.client("network-firewall", region_name=region)
    # Scan resource policies on firewall policies
    fw_policies = paginate(nfw, "list_firewall_policies", "FirewallPolicies")
    for fp in fw_policies:
        arn = fp.get("Arn", "")
        resp = safe(nfw.describe_resource_policy, ResourceArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "Network Firewall", terms, account_id)
            if hit:
                matches.append(hit)
    # Scan resource policies on rule groups
    rule_groups = paginate(nfw, "list_rule_groups", "RuleGroups")
    for rg in rule_groups:
        arn = rg.get("Arn", "")
        resp = safe(nfw.describe_resource_policy, ResourceArn=arn)
        if resp:
            hit = check_policy(policy_text(resp.get("Policy")), arn, "Network Firewall", terms, account_id)
            if hit:
                matches.append(hit)
    return matches


# ─── Regional orchestrator ──────────────────────────────────────────────────

REGIONAL_SCANNERS = [
    ("API Gateway", scan_api_gateway),
    ("Backup Vaults", scan_backup),
    ("CloudTrail", scan_cloudtrail),
    ("CloudWatch Logs", scan_cloudwatch_logs),
    ("CodeArtifact", scan_codeartifact),
    ("CodeBuild", scan_codebuild),
    ("DynamoDB", scan_dynamodb),
    ("Entity Resolution", scan_entity_resolution),
    ("EventBridge", scan_eventbridge),
    ("EventBridge Schemas", scan_eventbridge_schemas),
    ("Glue", scan_glue),
    ("KMS", scan_kms),
    ("Kinesis", scan_kinesis),
    ("Lambda", scan_lambda),
    ("Lex V2", scan_lex),
    ("OpenSearch", scan_opensearch),
    ("OpenSearch Serverless", scan_opensearch_serverless),
    ("S3 Express", scan_s3_express),
    ("S3 Tables", scan_s3_tables),
    ("Secrets Manager", scan_secrets_manager),
    ("SES v2", scan_ses),
    ("SNS", scan_sns),
    ("SQS", scan_sqs),
    ("ECR", scan_ecr),
    ("EFS", scan_efs),
    ("Redshift Serverless", scan_redshift_serverless),
    ("Rekognition", scan_rekognition),
    ("VPC Endpoints", scan_vpc_endpoints),
    ("MSK", scan_msk),
    ("Signer", scan_signer),
    ("VPC Lattice", scan_vpc_lattice),
    ("Network Firewall", scan_network_firewall),
]


def scan_regional_services(session, region, account_id, terms,
                           service_filter=None, exclude_filter=None):
    print(f"\n  Region: {region}")
    scanners = _filter_scanners(REGIONAL_SCANNERS, service_filter, exclude_filter)
    matches = []
    total = len(scanners)
    for i, (name, scanner) in enumerate(scanners, 1):
        progress(i, total, name, len(matches))
        matches.extend(scanner(session, region, account_id, terms))
    progress_done(total, len(matches))
    return matches


# ─── Main ────────────────────────────────────────────────────────────────────

def scan_account(session, account_id, terms, regions_arg, management_account,
                 service_filter=None, exclude_filter=None):
    """Run all scanners for a single account. Returns list of match dicts."""
    regions = get_regions(session, regions_arg)
    print(f"\n  Scanning regions: {', '.join(regions)}")

    matches = []
    matches.extend(scan_global_services(session, account_id, terms, management_account,
                                        service_filter, exclude_filter))
    for region in regions:
        matches.extend(scan_regional_services(session, region, account_id, terms,
                                              service_filter, exclude_filter))

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
    parser.add_argument("--workers", type=int, default=5,
                        help="Max parallel threads per service for policy fetches (default: 5)")
    parser.add_argument("--services", default=None,
                        help="Comma-separated list of services to scan (default: all). "
                             "Use --list-services to see available names.")
    parser.add_argument("--exclude-services", default=None,
                        help="Comma-separated list of services to skip")
    parser.add_argument("--list-services", action="store_true",
                        help="Print available service names and exit")
    args = parser.parse_args()

    # Handle --list-services
    all_service_names = [name for name, _ in GLOBAL_SCANNERS] + [name for name, _ in REGIONAL_SCANNERS]
    if args.list_services:
        print("Available services:")
        for name in all_service_names:
            print(f"  {name}")
        return

    # Validate: if one of account-ids / role-name is set, both must be
    if bool(args.account_ids) != bool(args.role_name):
        parser.error("--account-ids and --role-name must be used together")

    terms = [t.strip() for t in args.search.split(",")]
    print(f"Search strings: {terms}")
    print("=" * 70)

    global MAX_WORKERS
    MAX_WORKERS = args.workers
    reset_skipped_resources()

    # Build service filter
    service_filter = None
    if args.services:
        service_filter = {s.strip().lower() for s in args.services.split(",")}
    exclude_filter = set()
    if args.exclude_services:
        exclude_filter = {s.strip().lower() for s in args.exclude_services.split(",")}

    start_time = time.time()
    all_matches = []
    all_regions = set()

    if args.account_ids:
        # Multi-account mode: assume role in each account
        account_ids = [a.strip() for a in args.account_ids.split(",")]
        print(f"Multi-account mode: {len(account_ids)} account(s)")
        for acct in account_ids:
            session = assume_role(acct, args.role_name)
            matches, regions = scan_account(session, acct, terms, args.regions, args.management_account,
                                            service_filter, exclude_filter)
            all_matches.extend(matches)
            all_regions.update(regions)
    else:
        # Single-account mode: use current credentials
        session, account_id = get_session_info()
        matches, regions = scan_account(session, account_id, terms, args.regions, args.management_account,
                                        service_filter, exclude_filter)
        all_matches.extend(matches)
        all_regions.update(regions)

    # Summary
    elapsed = time.time() - start_time
    minutes, seconds = divmod(int(elapsed), 60)
    time_str = f"{minutes}m {seconds}s" if minutes else f"{seconds}s"

    skipped = get_skipped_resources()

    print("\n" + "=" * 70)
    print(f"Scan complete. {len(all_matches)} resource(s) matched in {time_str}.")
    if skipped:
        print(f"  {len(skipped)} resource(s) could not be scanned (see 'skipped_resources' in output).")
        # Summarize by error code
        code_counts: dict[str, int] = {}
        for s in skipped:
            code_counts[s["error_code"]] = code_counts.get(s["error_code"], 0) + 1
        for code, count in sorted(code_counts.items(), key=lambda x: -x[1]):
            print(f"    {code}: {count}")
    print("=" * 70)

    output = {
        "search_terms": terms,
        "regions_scanned": sorted(all_regions),
        "total_matches": len(all_matches),
        "matches": all_matches,
        "skipped_resources": skipped,
        "total_skipped": len(skipped),
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"Results written to {args.output}")


if __name__ == "__main__":
    main()
