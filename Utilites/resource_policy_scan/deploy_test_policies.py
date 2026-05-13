#!/usr/bin/env python3
"""
deploy_test_policies.py

Deploys the CloudFormation stack (test_resources.yaml) and creates additional
test resources with resource policies for services that don't support policies
via CloudFormation.

Usage:
    python3 deploy_test_policies.py [--region us-east-1] [--cleanup]
"""

import argparse
import json
import os
import random
import string
import time

import boto3
from botocore.exceptions import ClientError

ROLE_SUFFIX = "aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_AWSAdministratorAccess_6516ec63d4add68b"
PREFIX = "policy-scan-test"
ORG_ID = "o-dhuoj1jzwj"


def get_account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


def get_role_arn(account_id):
    return f"arn:aws:iam::{account_id}:role/{ROLE_SUFFIX}"


def policy_doc(role_arn, action, resource="*"):
    """Policy with wildcard principal + condition. Works for most services."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": action,
            "Resource": resource,
            "Condition": {
                "ArnEquals": {
                    "aws:PrincipalArn": role_arn,
                }
            },
        }]
    })


def policy_doc_direct(role_arn, action, resource="*"):
    """Policy with direct principal ARN. For services that reject wildcard principals."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": role_arn},
            "Action": action,
            "Resource": resource,
        }]
    })


def wait(seconds=2):
    time.sleep(seconds)


TEMPLATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_resources.yaml")
STACK_NAME = PREFIX


def deploy_cfn_stack(session, region, role_arn):
    """Deploy the CloudFormation stack and wait for completion."""
    print("=== CloudFormation Stack ===")
    cfn = session.client("cloudformation", region_name=region)

    with open(TEMPLATE_FILE, "r") as f:
        template_body = f.read()

    try:
        cfn.describe_stacks(StackName=STACK_NAME)
        # Stack exists — update it
        try:
            cfn.update_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Parameters=[{"ParameterKey": "IdentityCenterRoleArn", "ParameterValue": role_arn}],
                Capabilities=["CAPABILITY_NAMED_IAM"],
            )
            print(f"  Updating stack: {STACK_NAME}")
            waiter = cfn.get_waiter("stack_update_complete")
        except ClientError as e:
            if "No updates are to be performed" in str(e):
                print(f"  Stack {STACK_NAME} already up to date")
                return
            raise
    except ClientError:
        # Stack doesn't exist — create it
        cfn.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": "IdentityCenterRoleArn", "ParameterValue": role_arn}],
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
        print(f"  Creating stack: {STACK_NAME}")
        waiter = cfn.get_waiter("stack_create_complete")

    print("  Waiting for stack to complete (this may take several minutes)...")
    waiter.wait(StackName=STACK_NAME, WaiterConfig={"Delay": 15, "MaxAttempts": 60})
    print(f"  Stack {STACK_NAME} deployed successfully")


def delete_cfn_stack(session, region):
    """Delete the CloudFormation stack and wait for completion."""
    print("=== CloudFormation Stack ===")
    cfn = session.client("cloudformation", region_name=region)

    # Empty the S3 bucket first (can't delete non-empty buckets)
    try:
        s3 = session.client("s3", region_name=region)
        account_id = get_account_id(session)
        bucket_name = f"{PREFIX}-{account_id}"
        resp = s3.list_objects_v2(Bucket=bucket_name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        print(f"  Emptied bucket: {bucket_name}")
    except ClientError:
        pass

    try:
        cfn.delete_stack(StackName=STACK_NAME)
        print(f"  Deleting stack: {STACK_NAME}")
        waiter = cfn.get_waiter("stack_delete_complete")
        print("  Waiting for stack deletion...")
        waiter.wait(StackName=STACK_NAME, WaiterConfig={"Delay": 15, "MaxAttempts": 60})
        print(f"  Stack {STACK_NAME} deleted")
    except ClientError as e:
        print(f"  Stack deletion: {e}")


# ─── Individual resource creators ────────────────────────────────────────────

def setup_api_gateway(session, region, account_id, role_arn):
    """Create a REST API with a resource policy."""
    print("=== API Gateway ===")
    apigw = session.client("apigateway", region_name=region)
    try:
        resp = apigw.create_rest_api(
            name=PREFIX,
            description="Policy scan test API",
            policy=policy_doc(role_arn, "execute-api:Invoke",
                              f"arn:aws:execute-api:{region}:{account_id}:*/*"),
        )
        print(f"  Created REST API: {resp['id']}")
        return resp["id"]
    except ClientError as e:
        print(f"  Skipped: {e}")
        return None


def setup_codeartifact(session, region, account_id, role_arn):
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
            policyDocument=policy_doc(role_arn, "codeartifact:ListRepositoriesInDomain",
                                      f"arn:aws:codeartifact:{region}:{account_id}:domain/{PREFIX}"),
        )
        print("  Attached domain policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_codebuild(session, region, account_id, role_arn):
    """Create a CodeBuild report group with a resource policy."""
    print("=== CodeBuild ===")
    cb = session.client("codebuild", region_name=region)
    try:
        resp = cb.create_report_group(
            name=PREFIX,
            type="TEST",
            exportConfig={"exportConfigType": "NO_EXPORT"},
        )
        rg_arn = resp["reportGroup"]["arn"]
        print(f"  Created report group: {rg_arn}")
    except ClientError as e:
        print(f"  Report group exists or error: {e}")
        rg_arn = f"arn:aws:codebuild:{region}:{account_id}:report-group/{PREFIX}"
    try:
        codebuild_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowIdentityCenterRole",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "codebuild:BatchGetReportGroups",
                "Resource": rg_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": ORG_ID},
                    "ArnEquals": {"aws:PrincipalArn": role_arn},
                },
            }]
        })
        cb.put_resource_policy(
            resourceArn=rg_arn,
            policy=codebuild_policy,
        )
        print("  Attached report group policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_dynamodb(session, region, account_id, role_arn):
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
            Policy=policy_doc(role_arn, "dynamodb:DescribeTable", table_arn),
        )
        print("  Attached table policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_kinesis(session, region, account_id, role_arn):
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
            Policy=policy_doc_direct(role_arn, "kinesis:DescribeStream", stream_arn),
        )
        print("  Attached stream policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_eventbridge_schemas(session, region, account_id, role_arn):
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
            Policy=policy_doc(role_arn, "schemas:DescribeRegistry",
                              f"arn:aws:schemas:{region}:{account_id}:registry/{PREFIX}"),
        )
        print("  Attached registry policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_glue(session, region, account_id, role_arn):
    """Attach a resource policy to the Glue Data Catalog."""
    print("=== Glue ===")
    glue = session.client("glue", region_name=region)
    try:
        glue.put_resource_policy(
            PolicyInJson=policy_doc(role_arn, "glue:GetDatabase",
                                    f"arn:aws:glue:{region}:{account_id}:catalog"),
            EnableHybrid="TRUE",
        )
        print("  Attached Glue catalog resource policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_mediastore(session, region, account_id, role_arn):
    """MediaStore is discontinued — skip."""
    print("=== MediaStore ===")
    print("  Skipped: MediaStore is discontinued")


def setup_glacier(session, region, account_id, role_arn):
    """Glacier is discontinued for new accounts — skip."""
    print("=== Glacier ===")
    print("  Skipped: Glacier is discontinued for new accounts")


def setup_ses(session, region, account_id, role_arn):
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
            Policy=policy_doc(role_arn, "ses:SendEmail",
                              f"arn:aws:ses:{region}:{account_id}:identity/{identity}"),
        )
        print("  Attached identity policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_vpc_endpoint(session, region, account_id, role_arn):
    """Create a VPC endpoint with a resource policy."""
    print("=== VPC Endpoints ===")
    ec2 = session.client("ec2", region_name=region)
    # Use any available VPC
    vpcs = ec2.describe_vpcs()
    if not vpcs["Vpcs"]:
        print("  Skipped: no VPC found")
        return None
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    try:
        resp = ec2.create_vpc_endpoint(
            VpcId=vpc_id,
            ServiceName=f"com.amazonaws.{region}.s3",
            VpcEndpointType="Gateway",
            PolicyDocument=policy_doc(role_arn, "s3:GetObject"),
        )
        vpce_id = resp["VpcEndpoint"]["VpcEndpointId"]
        print(f"  Created VPC endpoint: {vpce_id}")
        return vpce_id
    except ClientError as e:
        print(f"  Skipped: {e}")
        return None


def setup_cloudtrail(session, region, account_id, role_arn):
    """Create a CloudTrail event data store with a resource policy."""
    print("=== CloudTrail ===")
    ct = session.client("cloudtrail", region_name=region)
    eds_arn = None
    # Check for an existing EDS we can reuse (including pending deletion)
    try:
        stores = ct.list_event_data_stores()
        for s in stores.get("EventDataStores", []):
            if PREFIX in s.get("Name", ""):
                status = s.get("Status")
                eds_arn = s["EventDataStoreArn"]
                if status == "PENDING_DELETION":
                    ct.restore_event_data_store(EventDataStore=eds_arn)
                    print(f"  Restored EDS from pending deletion: {eds_arn}")
                elif status == "ENABLED":
                    print(f"  Reusing existing EDS: {eds_arn}")
                break
    except ClientError:
        pass
    # Create a new one if none found
    if not eds_arn:
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        eds_name = f"{PREFIX}-{suffix}"
        try:
            resp = ct.create_event_data_store(
                Name=eds_name,
                RetentionPeriod=7,
                MultiRegionEnabled=False,
                TerminationProtectionEnabled=False,
            )
            eds_arn = resp["EventDataStoreArn"]
            print(f"  Created event data store: {eds_arn}")
        except ClientError as e:
            print(f"  EDS creation error: {e}")
            return
    try:
        ct.put_resource_policy(
            ResourceArn=eds_arn,
            ResourcePolicy=policy_doc(role_arn, "cloudtrail:GetEventDataStore", eds_arn),
        )
        print("  Attached resource policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_ssm(session, region, account_id, role_arn):
    """SSM resource policies only support account-level principals for OpsItems — skip."""
    print("=== Systems Manager ===")
    print("  Skipped: resource policies only support account-level principals for OpsItems")


def setup_entity_resolution(session, region, account_id, role_arn):
    """Attach a resource policy to the pre-existing Entity Resolution ID namespace."""
    print("=== Entity Resolution ===")
    er = session.client("entityresolution", region_name=region)
    ns_arn = "arn:aws:entityresolution:us-west-2:183068582925:idnamespace/test"
    try:
        er.put_policy(
            arn=ns_arn,
            policy=policy_doc(role_arn, "entityresolution:GetIdNamespace", ns_arn),
        )
        print("  Attached ID namespace policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_lex(session, region, account_id, role_arn):
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
            policy=policy_doc(role_arn, "lex:DescribeBot", bot_arn),
        )
        print("  Attached bot policy")
    except ClientError as e:
        if "PreconditionFailedException" in str(type(e)) or "ConflictException" in str(type(e)):
            try:
                lex.update_resource_policy(
                    resourceArn=bot_arn,
                    policy=policy_doc(role_arn, "lex:DescribeBot", bot_arn),
                    expectedRevisionId="*",
                )
                print("  Updated bot policy")
            except ClientError as e2:
                print(f"  Skipped policy: {e2}")
        else:
            print(f"  Skipped policy: {e}")


def setup_private_ca(session, region, account_id, role_arn):
    """Create a Private CA with a resource policy."""
    print("=== Private CA ===")
    pca = session.client("acm-pca", region_name=region)
    ca_arn = None
    # Check for existing CA we can reuse
    try:
        cas = pca.list_certificate_authorities()
        for ca in cas.get("CertificateAuthorities", []):
            subj = ca.get("CertificateAuthorityConfiguration", {}).get("Subject", {})
            if PREFIX in subj.get("CommonName", ""):
                status = ca.get("Status", "")
                ca_arn = ca["Arn"]
                if status == "DELETED":
                    pca.restore_certificate_authority(CertificateAuthorityArn=ca_arn)
                    print(f"  Restored CA from deleted state: {ca_arn}")
                    wait(5)
                elif status in ("ACTIVE", "CREATING", "PENDING_CERTIFICATE"):
                    print(f"  Reusing existing CA: {ca_arn}")
                break
    except ClientError:
        pass
    if not ca_arn:
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
            wait(5)
        except ClientError as e:
            print(f"  CA error: {e}")
            return
    try:
        pca_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowIdentityCenterRole",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "acm-pca:DescribeCertificateAuthority",
                "Resource": ca_arn,
                "Condition": {
                    "StringEquals": {"aws:PrincipalOrgID": ORG_ID},
                    "ArnEquals": {"aws:PrincipalArn": role_arn},
                },
            }]
        })
        pca.put_policy(
            ResourceArn=ca_arn,
            Policy=pca_policy,
        )
        print("  Attached CA policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_ssm_incidents(session, region, account_id, role_arn):
    """SSM Incident Manager is being deprecated — skip."""
    print("=== SSM Incident Manager ===")
    print("  Skipped: service is being deprecated")


# ─── Cleanup ─────────────────────────────────────────────────────────────────

def cleanup(session, region, account_id, skip_cfn=False):
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
        cb.delete_report_group(arn=f"arn:aws:codebuild:{region}:{account_id}:report-group/{PREFIX}", deleteReports=True)
        print(f"  Deleted CodeBuild report group: {PREFIX}")
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

    # Glue
    try:
        glue = session.client("glue", region_name=region)
        glue.delete_resource_policy()
        print("  Deleted Glue catalog resource policy")
    except ClientError as e:
        print(f"  Glue cleanup: {e}")

    # MediaStore — discontinued, nothing to clean up

    # Glacier — discontinued, nothing to clean up

    # SES
    try:
        sesv2 = session.client("sesv2", region_name=region)
        sesv2.delete_email_identity(EmailIdentity=f"{PREFIX}@example.com")
        print(f"  Deleted SES identity: {PREFIX}@example.com")
    except ClientError as e:
        print(f"  SES cleanup: {e}")

    # VPC Endpoints (find by S3 gateway type with our policy)
    try:
        ec2 = session.client("ec2", region_name=region)
        all_eps = ec2.describe_vpc_endpoints(
            Filters=[{"Name": "service-name", "Values": [f"com.amazonaws.{region}.s3"]}]
        )
        for ep in all_eps.get("VpcEndpoints", []):
            pol = json.dumps(ep.get("PolicyDocument", {}))
            if ROLE_SUFFIX in pol:
                ec2.delete_vpc_endpoints(VpcEndpointIds=[ep["VpcEndpointId"]])
                print(f"  Deleted VPC endpoint: {ep['VpcEndpointId']}")
    except ClientError as e:
        print(f"  VPC Endpoint cleanup: {e}")

    # CloudTrail
    try:
        ct = session.client("cloudtrail", region_name=region)
        stores = ct.list_event_data_stores()
        for s in stores.get("EventDataStores", []):
            if PREFIX in s.get("Name", "") and s.get("Status") == "ENABLED":
                ct.update_event_data_store(
                    EventDataStore=s["EventDataStoreArn"],
                    TerminationProtectionEnabled=False,
                )
                ct.delete_event_data_store(EventDataStore=s["EventDataStoreArn"])
                print(f"  Deleted CloudTrail EDS: {s['EventDataStoreArn']}")
    except ClientError as e:
        print(f"  CloudTrail cleanup: {e}")

    # SSM — skipped, no resources to clean up

    # Entity Resolution — using pre-existing ID namespace, don't delete it

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
            status = ca.get("Status", "")
            if PREFIX in subj.get("CommonName", ""):
                if status in ("ACTIVE", "DISABLED"):
                    pca.delete_certificate_authority(
                        CertificateAuthorityArn=ca["Arn"],
                        PermanentDeletionTimeInDays=7,
                    )
                    print(f"  Deleted Private CA: {ca['Arn']}")
                else:
                    print(f"  Skipped Private CA (status={status}): {ca['Arn']}")
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

    # CloudFormation stack (last — some SDK resources depend on CFN resources)
    if not skip_cfn:
        delete_cfn_stack(session, region)

    print("\nCleanup complete.")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Deploy test resource policies for non-CFN services.")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--cleanup", action="store_true", help="Delete all test resources instead of creating them")
    parser.add_argument("--skip-cfn", action="store_true", help="Skip CloudFormation stack deployment, only deploy SDK resources")
    args = parser.parse_args()

    session = boto3.Session()
    account_id = get_account_id(session)
    region = args.region

    print(f"Account: {account_id}")
    print(f"Region:  {region}")
    role_arn = get_role_arn(account_id)
    print(f"Role:    {role_arn}")
    print("=" * 70)

    if args.cleanup:
        cleanup(session, region, account_id, skip_cfn=args.skip_cfn)
        return

    # Deploy CloudFormation stack first (unless skipped)
    if not args.skip_cfn:
        deploy_cfn_stack(session, region, role_arn)
    else:
        print("Skipping CloudFormation stack deployment")

    # Then deploy non-CFN resources
    setup_api_gateway(session, region, account_id, role_arn)
    setup_codeartifact(session, region, account_id, role_arn)
    setup_codebuild(session, region, account_id, role_arn)
    setup_dynamodb(session, region, account_id, role_arn)
    setup_kinesis(session, region, account_id, role_arn)
    setup_eventbridge_schemas(session, region, account_id, role_arn)
    setup_glue(session, region, account_id, role_arn)
    setup_mediastore(session, region, account_id, role_arn)
    setup_glacier(session, region, account_id, role_arn)
    setup_ses(session, region, account_id, role_arn)
    setup_vpc_endpoint(session, region, account_id, role_arn)
    setup_cloudtrail(session, region, account_id, role_arn)
    setup_ssm(session, region, account_id, role_arn)
    setup_entity_resolution(session, region, account_id, role_arn)
    setup_lex(session, region, account_id, role_arn)
    setup_private_ca(session, region, account_id, role_arn)
    setup_ssm_incidents(session, region, account_id, role_arn)

    print("\n" + "=" * 70)
    print("All test resources deployed.")
    print("Run the scanner to verify:")
    print(f'  python3 scan_resource_policies.py --search "{role_arn}" --regions {region}')
    print("\nTo clean up:")
    print(f"  python3 deploy_test_policies.py --region {region} --cleanup")


if __name__ == "__main__":
    main()
