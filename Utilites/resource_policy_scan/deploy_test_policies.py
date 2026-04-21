#!/usr/bin/env python3
"""
deploy_test_policies.py

Creates test resources and attaches resource policies for services that don't
support resource policies via CloudFormation. Run this AFTER deploying the
test_resources.yaml stack.

Usage:
    python deploy_test_policies.py [--region us-east-1] [--cleanup]
"""

import argparse
import json
import time

import boto3
from botocore.exceptions import ClientError

ROLE_ARN = "arn:aws:iam::075384444871:role/aws-reserved/sso.amazonaws.com/us-east-1/AWSReservedSSO_AdministratorAccess_abc123def456"
PREFIX = "policy-scan-test"


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


def policy_doc(action, resource="*"):
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": ROLE_ARN},
            "Action": action,
            "Resource": resource,
        }]
    })


def wait(seconds=2):
    time.sleep(seconds)


# ─── Individual resource creators ────────────────────────────────────────────

def setup_api_gateway(session, region, account_id):
    """Create a REST API with a resource policy."""
    print("=== API Gateway ===")
    apigw = session.client("apigateway", region_name=region)
    try:
        resp = apigw.create_rest_api(
            name=PREFIX,
            description="Policy scan test API",
            policy=policy_doc("execute-api:Invoke",
                              f"arn:aws:execute-api:{region}:{account_id}:*/*"),
        )
        print(f"  Created REST API: {resp['id']}")
        return resp["id"]
    except ClientError as e:
        print(f"  Skipped: {e}")
        return None


def setup_codeartifact(session, region, account_id):
    """Create a CodeArtifact domain with a resource policy."""
    print("=== CodeArtifact ===")
    ca = session.client("codeartifact", region_name=region)
    try:
        ca.create_domain(domain=PREFIX)
        print(f"  Created domain: {PREFIX}")
    except ClientError as e:
        if "ConflictException" not in str(type(e)):
            print(f"  Domain exists or error: {e}")
    try:
        ca.put_domain_permissions_policy(
            domain=PREFIX,
            policyDocument=policy_doc("codeartifact:ListRepositoriesInDomain",
                                      f"arn:aws:codeartifact:{region}:{account_id}:domain/{PREFIX}"),
        )
        print("  Attached domain policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_codebuild(session, region, account_id):
    """Create a CodeBuild project with a resource policy."""
    print("=== CodeBuild ===")
    cb = session.client("codebuild", region_name=region)
    project_arn = f"arn:aws:codebuild:{region}:{account_id}:project/{PREFIX}"
    # Create a minimal project first
    try:
        cb.create_project(
            name=PREFIX,
            source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo test"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=f"arn:aws:iam::{account_id}:role/policy-scan-test-lambda-role",
        )
        print(f"  Created project: {PREFIX}")
    except ClientError as e:
        print(f"  Project exists or error: {e}")
    # CodeBuild resource policies only apply to report groups and shared projects
    try:
        cb.put_resource_policy(
            resourceArn=project_arn,
            policy=policy_doc("codebuild:BatchGetProjects", project_arn),
        )
        print("  Attached project policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_dynamodb(session, region, account_id):
    """Create a DynamoDB table with a resource policy."""
    print("=== DynamoDB ===")
    ddb = session.client("dynamodb", region_name=region)
    table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{PREFIX}"
    try:
        ddb.create_table(
            TableName=PREFIX,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        print(f"  Created table: {PREFIX}")
        waiter = ddb.get_waiter("table_exists")
        waiter.wait(TableName=PREFIX)
    except ClientError as e:
        print(f"  Table exists or error: {e}")
    try:
        ddb.put_resource_policy(
            ResourceArn=table_arn,
            Policy=policy_doc("dynamodb:DescribeTable", table_arn),
        )
        print("  Attached table policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_kinesis(session, region, account_id):
    """Create a Kinesis stream with a resource policy."""
    print("=== Kinesis ===")
    kinesis = session.client("kinesis", region_name=region)
    try:
        kinesis.create_stream(StreamName=PREFIX, StreamModeDetails={"StreamMode": "ON_DEMAND"})
        print(f"  Created stream: {PREFIX}")
        waiter = kinesis.get_waiter("stream_exists")
        waiter.wait(StreamName=PREFIX)
    except ClientError as e:
        print(f"  Stream exists or error: {e}")
    try:
        desc = kinesis.describe_stream_summary(StreamName=PREFIX)
        stream_arn = desc["StreamDescriptionSummary"]["StreamARN"]
        kinesis.put_resource_policy(
            ResourceARN=stream_arn,
            Policy=policy_doc("kinesis:DescribeStream", stream_arn),
        )
        print("  Attached stream policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_eventbridge_schemas(session, region, account_id):
    """Create an EventBridge Schemas registry with a resource policy."""
    print("=== EventBridge Schemas ===")
    schemas = session.client("schemas", region_name=region)
    try:
        schemas.create_registry(RegistryName=PREFIX, Description="Policy scan test")
        print(f"  Created registry: {PREFIX}")
    except ClientError as e:
        print(f"  Registry exists or error: {e}")
    try:
        schemas.put_resource_policy(
            RegistryName=PREFIX,
            Policy=policy_doc("schemas:DescribeRegistry",
                              f"arn:aws:schemas:{region}:{account_id}:registry/{PREFIX}"),
        )
        print("  Attached registry policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_mediastore(session, region, account_id):
    """Create a MediaStore container with a resource policy."""
    print("=== MediaStore ===")
    ms = session.client("mediastore", region_name=region)
    try:
        ms.create_container(ContainerName=PREFIX)
        print(f"  Created container: {PREFIX}")
        # Wait for container to become active
        for _ in range(30):
            resp = ms.describe_container(ContainerName=PREFIX)
            if resp["Container"]["Status"] == "ACTIVE":
                break
            wait(5)
    except ClientError as e:
        print(f"  Container exists or error: {e}")
    try:
        ms.put_container_policy(
            ContainerName=PREFIX,
            Policy=policy_doc("mediastore:DescribeContainer",
                              f"arn:aws:mediastore:{region}:{account_id}:container/{PREFIX}"),
        )
        print("  Attached container policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_glacier(session, region, account_id):
    """Create a Glacier vault with an access policy."""
    print("=== Glacier ===")
    glacier = session.client("glacier", region_name=region)
    try:
        glacier.create_vault(accountId=account_id, vaultName=PREFIX)
        print(f"  Created vault: {PREFIX}")
    except ClientError as e:
        print(f"  Vault exists or error: {e}")
    try:
        glacier.set_vault_access_policy(
            accountId=account_id,
            vaultName=PREFIX,
            policy={"Policy": policy_doc("glacier:DescribeVault",
                                         f"arn:aws:glacier:{region}:{account_id}:vaults/{PREFIX}")},
        )
        print("  Attached vault access policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_ses(session, region, account_id):
    """Create an SES identity with a sending policy."""
    print("=== SES ===")
    sesv2 = session.client("sesv2", region_name=region)
    ses = session.client("ses", region_name=region)
    identity = f"{PREFIX}@example.com"
    try:
        sesv2.create_email_identity(EmailIdentity=identity)
        print(f"  Created identity: {identity}")
    except ClientError as e:
        print(f"  Identity exists or error: {e}")
    try:
        ses.put_identity_policy(
            Identity=identity,
            PolicyName="test-policy",
            Policy=policy_doc("ses:GetIdentityVerificationAttributes",
                              f"arn:aws:ses:{region}:{account_id}:identity/{identity}"),
        )
        print("  Attached identity policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_vpc_endpoint(session, region, account_id):
    """Create a VPC endpoint with a resource policy."""
    print("=== VPC Endpoints ===")
    ec2 = session.client("ec2", region_name=region)
    # Find default VPC
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    if not vpcs["Vpcs"]:
        print("  Skipped: no default VPC found")
        return None
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    try:
        resp = ec2.create_vpc_endpoint(
            VpcId=vpc_id,
            ServiceName=f"com.amazonaws.{region}.s3",
            VpcEndpointType="Gateway",
            PolicyDocument=policy_doc("s3:GetObject"),
        )
        vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
        print(f"  Created VPC endpoint: {vpce_id}")
        return vpce_id
    except ClientError as e:
        print(f"  Skipped: {e}")
        return None


def setup_cloudtrail(session, region, account_id):
    """Create a CloudTrail event data store with a resource policy."""
    print("=== CloudTrail ===")
    ct = session.client("cloudtrail", region_name=region)
    try:
        resp = ct.create_event_data_store(
            Name=PREFIX,
            RetentionPeriod=7,
            MultiRegionEnabled=False,
        )
        eds_arn = resp["EventDataStoreArn"]
        print(f"  Created event data store: {eds_arn}")
    except ClientError as e:
        print(f"  EDS exists or error: {e}")
        # Try to find existing one
        try:
            stores = ct.list_event_data_stores()
            for s in stores.get("EventDataStores", []):
                if PREFIX in s.get("Name", ""):
                    eds_arn = s["EventDataStoreArn"]
                    break
            else:
                return
        except ClientError:
            return
    try:
        ct.put_resource_policy(
            ResourceArn=eds_arn,
            ResourcePolicy=policy_doc("cloudtrail:GetEventDataStore", eds_arn),
        )
        print("  Attached resource policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_ssm(session, region, account_id):
    """Create an SSM document and share it (resource policy equivalent)."""
    print("=== Systems Manager ===")
    ssm = session.client("ssm", region_name=region)
    doc_name = f"{PREFIX}-doc"
    try:
        ssm.create_document(
            Name=doc_name,
            Content=json.dumps({
                "schemaVersion": "2.2",
                "description": "Policy scan test document",
                "mainSteps": [{"action": "aws:runShellScript", "name": "test",
                               "inputs": {"runCommand": ["echo test"]}}]
            }),
            DocumentType="Command",
            DocumentFormat="JSON",
        )
        print(f"  Created document: {doc_name}")
    except ClientError as e:
        print(f"  Document exists or error: {e}")
    # SSM OpsItemGroup resource policy
    arn = f"arn:aws:ssm:{region}:{account_id}:opsitemgroup/default"
    try:
        ssm.put_resource_policy(
            ResourceArn=arn,
            Policy=policy_doc("ssm:GetOpsItem", arn),
        )
        print("  Attached OpsItemGroup resource policy")
    except ClientError as e:
        print(f"  Skipped OpsItemGroup policy: {e}")


def setup_entity_resolution(session, region, account_id):
    """Create an Entity Resolution schema mapping with a resource policy."""
    print("=== Entity Resolution ===")
    er = session.client("entityresolution", region_name=region)
    schema_name = PREFIX.replace("-", "")  # no hyphens allowed
    try:
        resp = er.create_schema_mapping(
            schemaName=schema_name,
            mappedInputFields=[{
                "fieldName": "id",
                "type": "UNIQUE_ID",
            }],
        )
        schema_arn = resp["schemaArn"]
        print(f"  Created schema mapping: {schema_arn}")
    except ClientError as e:
        print(f"  Schema exists or error: {e}")
        try:
            resp = er.get_schema_mapping(schemaName=schema_name)
            schema_arn = resp["schemaArn"]
        except ClientError:
            return
    try:
        er.put_policy(
            arn=schema_arn,
            policy=policy_doc("entityresolution:GetSchemaMapping", schema_arn),
        )
        print("  Attached schema policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_lex(session, region, account_id):
    """Create a Lex V2 bot with a resource policy."""
    print("=== Lex V2 ===")
    lex = session.client("lexv2-models", region_name=region)
    try:
        resp = lex.create_bot(
            botName=PREFIX,
            roleArn=f"arn:aws:iam::{account_id}:role/policy-scan-test-lambda-role",
            dataPrivacy={"childDirected": False},
            idleSessionTTLInSeconds=300,
        )
        bot_id = resp["botId"]
        print(f"  Created bot: {bot_id}")
    except ClientError as e:
        print(f"  Bot exists or error: {e}")
        try:
            bots = lex.list_bots(filters=[{"name": "BotName", "values": [PREFIX], "operator": "EQ"}])
            for b in bots.get("botSummaries", []):
                bot_id = b["botId"]
                break
            else:
                return
        except ClientError:
            return
    bot_arn = f"arn:aws:lex:{region}:{account_id}:bot/{bot_id}"
    try:
        lex.create_resource_policy(
            resourceArn=bot_arn,
            policy=policy_doc("lex:DescribeBot", bot_arn),
        )
        print("  Attached bot policy")
    except ClientError as e:
        if "PreconditionFailedException" in str(type(e)) or "ConflictException" in str(type(e)):
            try:
                lex.update_resource_policy(
                    resourceArn=bot_arn,
                    policy=policy_doc("lex:DescribeBot", bot_arn),
                    expectedRevisionId="*",
                )
                print("  Updated bot policy")
            except ClientError as e2:
                print(f"  Skipped policy: {e2}")
        else:
            print(f"  Skipped policy: {e}")


def setup_private_ca(session, region, account_id):
    """Create a Private CA with a resource policy."""
    print("=== Private CA ===")
    pca = session.client("acm-pca", region_name=region)
    try:
        resp = pca.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "RSA_2048",
                "SigningAlgorithm": "SHA256WITHRSA",
                "Subject": {"CommonName": f"{PREFIX}.example.com"},
            },
            CertificateAuthorityType="ROOT",
        )
        ca_arn = resp["CertificateAuthorityArn"]
        print(f"  Created CA: {ca_arn}")
    except ClientError as e:
        print(f"  CA error: {e}")
        return
    wait(5)
    try:
        pca.put_policy(
            ResourceArn=ca_arn,
            Policy=policy_doc("acm-pca:DescribeCertificateAuthority", ca_arn),
        )
        print("  Attached CA policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_ssm_incidents(session, region, account_id):
    """Create an SSM Incident Manager response plan with a resource policy."""
    print("=== SSM Incident Manager ===")
    inc = session.client("ssm-incidents", region_name=region)
    try:
        resp = inc.create_response_plan(
            name=PREFIX,
            incidentTemplate={
                "title": "Policy scan test incident",
                "impact": 5,
            },
        )
        rp_arn = resp["arn"]
        print(f"  Created response plan: {rp_arn}")
    except ClientError as e:
        print(f"  Response plan exists or error: {e}")
        try:
            plans = inc.list_response_plans()
            for p in plans.get("responsePlanSummaries", []):
                if PREFIX in p["arn"]:
                    rp_arn = p["arn"]
                    break
            else:
                return
        except ClientError:
            return
    try:
        inc.put_resource_policy(
            resourceArn=rp_arn,
            policy=policy_doc("ssm-incidents:GetResponsePlan", rp_arn),
        )
        print("  Attached response plan policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


# ─── Cleanup ─────────────────────────────────────────────────────────────────

def cleanup(session, region, account_id):
    """Delete all test resources created by this script."""
    print("\n=== Cleaning up non-CFN resources ===\n")

    # API Gateway
    try:
        apigw = session.client("apigateway", region_name=region)
        for api in apigw.get_rest_apis().get("items", []):
            if api["name"] == PREFIX:
                apigw.delete_rest_api(restApiId=api["id"])
                print(f"  Deleted REST API: {api['id']}")
    except ClientError as e:
        print(f"  API Gateway cleanup: {e}")

    # CodeArtifact
    try:
        ca = session.client("codeartifact", region_name=region)
        ca.delete_domain(domain=PREFIX)
        print(f"  Deleted CodeArtifact domain: {PREFIX}")
    except ClientError as e:
        print(f"  CodeArtifact cleanup: {e}")

    # CodeBuild
    try:
        cb = session.client("codebuild", region_name=region)
        cb.delete_project(name=PREFIX)
        print(f"  Deleted CodeBuild project: {PREFIX}")
    except ClientError as e:
        print(f"  CodeBuild cleanup: {e}")

    # DynamoDB
    try:
        ddb = session.client("dynamodb", region_name=region)
        ddb.delete_table(TableName=PREFIX)
        print(f"  Deleted DynamoDB table: {PREFIX}")
    except ClientError as e:
        print(f"  DynamoDB cleanup: {e}")

    # Kinesis
    try:
        kinesis = session.client("kinesis", region_name=region)
        kinesis.delete_stream(StreamName=PREFIX, EnforceConsumerDeletion=True)
        print(f"  Deleted Kinesis stream: {PREFIX}")
    except ClientError as e:
        print(f"  Kinesis cleanup: {e}")

    # EventBridge Schemas
    try:
        schemas = session.client("schemas", region_name=region)
        schemas.delete_registry(RegistryName=PREFIX)
        print(f"  Deleted Schemas registry: {PREFIX}")
    except ClientError as e:
        print(f"  Schemas cleanup: {e}")

    # MediaStore
    try:
        ms = session.client("mediastore", region_name=region)
        ms.delete_container(ContainerName=PREFIX)
        print(f"  Deleted MediaStore container: {PREFIX}")
    except ClientError as e:
        print(f"  MediaStore cleanup: {e}")

    # Glacier
    try:
        glacier = session.client("glacier", region_name=region)
        glacier.delete_vault(accountId=account_id, vaultName=PREFIX)
        print(f"  Deleted Glacier vault: {PREFIX}")
    except ClientError as e:
        print(f"  Glacier cleanup: {e}")

    # SES
    try:
        sesv2 = session.client("sesv2", region_name=region)
        sesv2.delete_email_identity(EmailIdentity=f"{PREFIX}@example.com")
        print(f"  Deleted SES identity: {PREFIX}@example.com")
    except ClientError as e:
        print(f"  SES cleanup: {e}")

    # VPC Endpoints
    try:
        ec2 = session.client("ec2", region_name=region)
        eps = ec2.describe_vpc_endpoints(Filters=[{"Name": "tag:Name", "Values": [PREFIX]}])
        # Also find by checking all gateway endpoints
        all_eps = ec2.describe_vpc_endpoints()
        for ep in all_eps.get("VpcEndpoints", []):
            # Delete ones we likely created (recent, gateway type to S3)
            pass
    except ClientError as e:
        print(f"  VPC Endpoint cleanup: {e}")

    # CloudTrail
    try:
        ct = session.client("cloudtrail", region_name=region)
        stores = ct.list_event_data_stores()
        for s in stores.get("EventDataStores", []):
            if PREFIX in s.get("Name", ""):
                ct.delete_event_data_store(EventDataStore=s["EventDataStoreArn"])
                print(f"  Deleted CloudTrail EDS: {s['EventDataStoreArn']}")
    except ClientError as e:
        print(f"  CloudTrail cleanup: {e}")

    # SSM
    try:
        ssm = session.client("ssm", region_name=region)
        ssm.delete_document(Name=f"{PREFIX}-doc")
        print(f"  Deleted SSM document: {PREFIX}-doc")
    except ClientError as e:
        print(f"  SSM cleanup: {e}")

    # Entity Resolution
    try:
        er = session.client("entityresolution", region_name=region)
        er.delete_schema_mapping(schemaName=PREFIX.replace("-", ""))
        print(f"  Deleted Entity Resolution schema: {PREFIX.replace('-', '')}")
    except ClientError as e:
        print(f"  Entity Resolution cleanup: {e}")

    # Lex V2
    try:
        lex = session.client("lexv2-models", region_name=region)
        bots = lex.list_bots(filters=[{"name": "BotName", "values": [PREFIX], "operator": "EQ"}])
        for b in bots.get("botSummaries", []):
            lex.delete_bot(botId=b["botId"], skipResourceInUseCheck=True)
            print(f"  Deleted Lex bot: {b['botId']}")
    except ClientError as e:
        print(f"  Lex cleanup: {e}")

    # Private CA
    try:
        pca = session.client("acm-pca", region_name=region)
        cas = pca.list_certificate_authorities()
        for ca in cas.get("CertificateAuthorities", []):
            subj = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {})
            if PREFIX in subj.get("CommonName", ""):
                pca.update_certificate_authority(
                    CertificateAuthorityArn=ca["Arn"],
                    Status="DISABLED",
                )
                pca.delete_certificate_authority(
                    CertificateAuthorityArn=ca["Arn"],
                    PermanentDeletionTimeInDays=7,
                )
                print(f"  Deleted Private CA: {ca['Arn']}")
    except ClientError as e:
        print(f"  Private CA cleanup: {e}")

    # SSM Incidents
    try:
        inc = session.client("ssm-incidents", region_name=region)
        plans = inc.list_response_plans()
        for p in plans.get("responsePlanSummaries", []):
            if PREFIX in p["arn"]:
                inc.delete_response_plan(arn=p["arn"])
                print(f"  Deleted response plan: {p['arn']}")
    except ClientError as e:
        print(f"  SSM Incidents cleanup: {e}")

    print("\nCleanup complete. Don't forget to delete the CFN stack too:")
    print("  aws cloudformation delete-stack --stack-name policy-scan-test")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Deploy test resource policies for non-CFN services.")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--cleanup", action="store_true", help="Delete all test resources instead of creating them")
    args = parser.parse_args()

    session = boto3.Session()
    account_id = get_account_id(session)
    region = args.region

    print(f"Account: {account_id}")
    print(f"Region:  {region}")
    print(f"Role:    {ROLE_ARN}")
    print("=" * 70)

    if args.cleanup:
        cleanup(session, region, account_id)
        return

    setup_api_gateway(session, region, account_id)
    setup_codeartifact(session, region, account_id)
    setup_codebuild(session, region, account_id)
    setup_dynamodb(session, region, account_id)
    setup_kinesis(session, region, account_id)
    setup_eventbridge_schemas(session, region, account_id)
    setup_mediastore(session, region, account_id)
    setup_glacier(session, region, account_id)
    setup_ses(session, region, account_id)
    setup_vpc_endpoint(session, region, account_id)
    setup_cloudtrail(session, region, account_id)
    setup_ssm(session, region, account_id)
    setup_entity_resolution(session, region, account_id)
    setup_lex(session, region, account_id)
    setup_private_ca(session, region, account_id)
    setup_ssm_incidents(session, region, account_id)

    print("\n" + "=" * 70)
    print("All non-CFN test resources deployed.")
    print("Run the scanner to verify:")
    print(f'  python scan_resource_policies.py --search "{ROLE_ARN}" --regions {region}')
    print("\nTo clean up:")
    print(f"  python deploy_test_policies.py --region {region} --cleanup")
    print(f"  aws cloudformation delete-stack --stack-name {PREFIX}")


if __name__ == "__main__":
    main()
