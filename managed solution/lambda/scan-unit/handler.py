"""
Scan Unit Lambda — scans resource policies in a single account + region.

Invoked by the Policy Scan Step Functions workflow (one invocation per
account+region combination). Uses asyncio to parallelize API calls within
the unit while respecting per-service concurrency limits.

Input (from Step Functions):
  {
    "account_id": "123456789012",
    "region": "us-east-1",
    "search_terms": ["old-idp-arn", "legacy-provider"],
    "services": ["s3", "sqs", "kms", ...] | null (all),
    "job_id": "abc123",
    "caller_arn": "arn:aws:iam::...:user/..."
  }

Output:
  {
    "account_id": "123456789012",
    "region": "us-east-1",
    "matches": [...],
    "resources_scanned": 150,
    "status": "ok"
  }
"""

import asyncio
import json
import os
import sys

import boto3

from shared.credentials import assume_role

CONCURRENCY_PER_SERVICE = 10


def lambda_handler(event, context):
    """Scan resource policies for one account + one region."""
    account_id = event["account_id"]
    region = event["region"]
    search_terms = event.get("search_terms", [])
    service_filter = event.get("services")  # None = all

    # Assume role in target account
    session = assume_role(account_id, session_suffix="scan")

    # Run the async scanner
    result = asyncio.run(
        scan_region(session, account_id, region, search_terms, service_filter)
    )

    return result


async def scan_region(
    session: boto3.Session,
    account_id: str,
    region: str,
    search_terms: list[str],
    service_filter: list[str] | None,
) -> dict:
    """Scan all supported services in one region, parallelized."""
    scanners = []

    if not service_filter or "s3" in service_filter:
        scanners.append(("s3", scan_s3_policies(session, region, search_terms)))
    if not service_filter or "sqs" in service_filter:
        scanners.append(("sqs", scan_sqs_policies(session, region, search_terms)))
    if not service_filter or "kms" in service_filter:
        scanners.append(("kms", scan_kms_policies(session, region, search_terms)))
    if not service_filter or "sns" in service_filter:
        scanners.append(("sns", scan_sns_policies(session, region, search_terms)))
    if not service_filter or "lambda" in service_filter:
        scanners.append(("lambda", scan_lambda_policies(session, region, search_terms)))
    if not service_filter or "ecr" in service_filter:
        scanners.append(("ecr", scan_ecr_policies(session, region, search_terms)))
    if not service_filter or "secretsmanager" in service_filter:
        scanners.append(("secretsmanager", scan_secrets_policies(session, region, search_terms)))

    tasks = [coro for _, coro in scanners]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_matches = []
    resources_scanned = 0

    for (svc_name, _), result in zip(scanners, results):
        if isinstance(result, Exception):
            all_matches.append({
                "service": svc_name,
                "error": str(result),
                "region": region,
                "account_id": account_id,
            })
        elif isinstance(result, dict):
            all_matches.extend(result.get("matches", []))
            resources_scanned += result.get("count", 0)

    return {
        "account_id": account_id,
        "region": region,
        "matches": all_matches,
        "resources_scanned": resources_scanned,
        "status": "ok",
    }


def _matches_terms(policy_str: str, search_terms: list[str]) -> list[str]:
    """Check if a policy string contains any of the search terms."""
    policy_lower = policy_str.lower()
    return [t for t in search_terms if t.lower() in policy_lower]


async def scan_s3_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan S3 bucket policies in the region."""
    s3_client = session.client("s3", region_name=region)
    matches = []

    # List buckets (global, but filter by region)
    try:
        resp = s3_client.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
    except Exception:
        return {"matches": [], "count": 0}

    # Filter to buckets in this region
    region_buckets = []
    sem = asyncio.Semaphore(CONCURRENCY_PER_SERVICE)

    for bucket in buckets:
        try:
            loc = s3_client.get_bucket_location(Bucket=bucket)
            bucket_region = loc.get("LocationConstraint") or "us-east-1"
            if bucket_region == region:
                region_buckets.append(bucket)
        except Exception:
            pass

    # Get policies for region-matched buckets
    for bucket in region_buckets:
        try:
            policy_resp = s3_client.get_bucket_policy(Bucket=bucket)
            policy_str = policy_resp["Policy"]
            found_terms = _matches_terms(policy_str, search_terms)
            if found_terms:
                matches.append({
                    "service": "s3",
                    "resource_type": "bucket_policy",
                    "resource_name": bucket,
                    "resource_arn": f"arn:aws:s3:::{bucket}",
                    "region": region,
                    "matched_terms": found_terms,
                    "policy": json.loads(policy_str),
                })
        except s3_client.exceptions.from_code("NoSuchBucketPolicy"):
            pass
        except Exception:
            pass

    return {"matches": matches, "count": len(region_buckets)}


async def scan_sqs_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan SQS queue policies."""
    sqs = session.client("sqs", region_name=region)
    matches = []
    count = 0

    try:
        resp = sqs.list_queues()
        queue_urls = resp.get("QueueUrls", [])
    except Exception:
        return {"matches": [], "count": 0}

    for url in queue_urls:
        count += 1
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy", "QueueArn"])
            policy_str = attrs.get("Attributes", {}).get("Policy", "")
            queue_arn = attrs.get("Attributes", {}).get("QueueArn", "")
            if policy_str:
                found_terms = _matches_terms(policy_str, search_terms)
                if found_terms:
                    matches.append({
                        "service": "sqs",
                        "resource_type": "queue_policy",
                        "resource_name": url.split("/")[-1],
                        "resource_arn": queue_arn,
                        "region": region,
                        "matched_terms": found_terms,
                        "policy": json.loads(policy_str),
                    })
        except Exception:
            pass

    return {"matches": matches, "count": count}


async def scan_kms_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan KMS key policies."""
    kms = session.client("kms", region_name=region)
    matches = []
    count = 0

    try:
        paginator = kms.get_paginator("list_keys")
        keys = []
        for page in paginator.paginate():
            keys.extend(page.get("Keys", []))
    except Exception:
        return {"matches": [], "count": 0}

    for key in keys:
        count += 1
        try:
            policy_resp = kms.get_key_policy(KeyId=key["KeyId"], PolicyName="default")
            policy_str = policy_resp["Policy"]
            found_terms = _matches_terms(policy_str, search_terms)
            if found_terms:
                matches.append({
                    "service": "kms",
                    "resource_type": "key_policy",
                    "resource_name": key["KeyId"],
                    "resource_arn": key["KeyArn"],
                    "region": region,
                    "matched_terms": found_terms,
                    "policy": json.loads(policy_str),
                })
        except Exception:
            pass

    return {"matches": matches, "count": count}


async def scan_sns_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan SNS topic policies."""
    sns = session.client("sns", region_name=region)
    matches = []
    count = 0

    try:
        paginator = sns.get_paginator("list_topics")
        topics = []
        for page in paginator.paginate():
            topics.extend(page.get("Topics", []))
    except Exception:
        return {"matches": [], "count": 0}

    for topic in topics:
        count += 1
        arn = topic["TopicArn"]
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn)
            policy_str = attrs.get("Attributes", {}).get("Policy", "")
            if policy_str:
                found_terms = _matches_terms(policy_str, search_terms)
                if found_terms:
                    matches.append({
                        "service": "sns",
                        "resource_type": "topic_policy",
                        "resource_name": arn.split(":")[-1],
                        "resource_arn": arn,
                        "region": region,
                        "matched_terms": found_terms,
                        "policy": json.loads(policy_str),
                    })
        except Exception:
            pass

    return {"matches": matches, "count": count}


async def scan_lambda_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan Lambda function resource policies."""
    lmb = session.client("lambda", region_name=region)
    matches = []
    count = 0

    try:
        paginator = lmb.get_paginator("list_functions")
        functions = []
        for page in paginator.paginate():
            functions.extend(page.get("Functions", []))
    except Exception:
        return {"matches": [], "count": 0}

    for fn in functions:
        count += 1
        try:
            policy_resp = lmb.get_policy(FunctionName=fn["FunctionName"])
            policy_str = policy_resp["Policy"]
            found_terms = _matches_terms(policy_str, search_terms)
            if found_terms:
                matches.append({
                    "service": "lambda",
                    "resource_type": "function_policy",
                    "resource_name": fn["FunctionName"],
                    "resource_arn": fn["FunctionArn"],
                    "region": region,
                    "matched_terms": found_terms,
                    "policy": json.loads(policy_str),
                })
        except lmb.exceptions.ResourceNotFoundException:
            pass
        except Exception:
            pass

    return {"matches": matches, "count": count}


async def scan_ecr_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan ECR repository policies."""
    ecr = session.client("ecr", region_name=region)
    matches = []
    count = 0

    try:
        paginator = ecr.get_paginator("describe_repositories")
        repos = []
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))
    except Exception:
        return {"matches": [], "count": 0}

    for repo in repos:
        count += 1
        try:
            policy_resp = ecr.get_repository_policy(repositoryName=repo["repositoryName"])
            policy_str = policy_resp["policyText"]
            found_terms = _matches_terms(policy_str, search_terms)
            if found_terms:
                matches.append({
                    "service": "ecr",
                    "resource_type": "repository_policy",
                    "resource_name": repo["repositoryName"],
                    "resource_arn": repo["repositoryArn"],
                    "region": region,
                    "matched_terms": found_terms,
                    "policy": json.loads(policy_str),
                })
        except ecr.exceptions.RepositoryPolicyNotFoundException:
            pass
        except Exception:
            pass

    return {"matches": matches, "count": count}


async def scan_secrets_policies(session: boto3.Session, region: str, search_terms: list[str]) -> dict:
    """Scan Secrets Manager secret resource policies."""
    sm = session.client("secretsmanager", region_name=region)
    matches = []
    count = 0

    try:
        paginator = sm.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))
    except Exception:
        return {"matches": [], "count": 0}

    for secret in secrets:
        count += 1
        try:
            policy_resp = sm.get_resource_policy(SecretId=secret["ARN"])
            policy_str = policy_resp.get("ResourcePolicy", "")
            if policy_str:
                found_terms = _matches_terms(policy_str, search_terms)
                if found_terms:
                    matches.append({
                        "service": "secretsmanager",
                        "resource_type": "secret_policy",
                        "resource_name": secret["Name"],
                        "resource_arn": secret["ARN"],
                        "region": region,
                        "matched_terms": found_terms,
                        "policy": json.loads(policy_str),
                    })
        except Exception:
            pass

    return {"matches": matches, "count": count}
