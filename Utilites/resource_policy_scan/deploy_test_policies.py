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

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
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
                "Principal": {"AWS": role_arn},
                "Action": "codebuild:BatchGetReportGroups",
                "Resource": rg_arn,
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
        # Kinesis resource policies need account root as principal
        kinesis_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowIdentityCenterRole",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kinesis:DescribeStream",
                "Resource": stream_arn,
            }]
        })
        kinesis.put_resource_policy(ResourceARN=stream_arn, Policy=kinesis_policy)
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
    """Attach a resource policy to an Entity Resolution ID namespace."""
    print("=== Entity Resolution ===")
    er = session.client("entityresolution", region_name=region)
    ns_name = "policy-scan-test"
    ns_arn = f"arn:aws:entityresolution:{region}:{account_id}:idnamespace/{ns_name}"
    # Create namespace if it doesn't exist
    try:
        er.create_id_namespace(
            idNamespaceName=ns_name,
            type="SOURCE",
        )
        print(f"  Created ID namespace: {ns_name}")
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            print(f"  ID namespace already exists")
        else:
            print(f"  Could not create ID namespace: {e}")
            return
    try:
        er_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowCrossAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["entityresolution:GetIdNamespace"],
                "Resource": ns_arn,
            }]
        })
        er.put_policy(arn=ns_arn, policy=er_policy)
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
                "Principal": {"AWS": role_arn},
                "Action": "acm-pca:DescribeCertificateAuthority",
                "Resource": ca_arn,
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


def setup_msk(session, region, account_id, role_arn):
    """Create an MSK Serverless cluster with a cluster policy."""
    print("=== MSK ===")
    kafka = session.client("kafka", region_name=region)
    cluster_arn = None
    # Check for existing cluster
    try:
        clusters = kafka.list_clusters_v2()
        for c in clusters.get("ClusterInfoList", []):
            if c.get("ClusterName", "") == PREFIX:
                cluster_arn = c["ClusterArn"]
                print(f"  Reusing existing cluster: {cluster_arn}")
                break
    except ClientError as e:
        print(f"  List error: {e}")
    if not cluster_arn:
        # MSK provisioned clusters are expensive and slow — use serverless
        ec2 = session.client("ec2", region_name=region)
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if not vpcs["Vpcs"]:
            vpcs = ec2.describe_vpcs()
        if not vpcs["Vpcs"]:
            print("  Skipped: no VPC available")
            return
        vpc_id = vpcs["Vpcs"][0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        subnet_ids = [s["SubnetId"] for s in subnets["Subnets"][:2]]
        sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}])
        sg_id = sgs["SecurityGroups"][0]["GroupId"] if sgs["SecurityGroups"] else None
        if len(subnet_ids) < 2 or not sg_id:
            print("  Skipped: insufficient subnets or security groups")
            return
        try:
            resp = kafka.create_cluster_v2(
                ClusterName=PREFIX,
                Serverless={
                    "VpcConfigs": [{
                        "SubnetIds": subnet_ids,
                        "SecurityGroupIds": [sg_id],
                    }],
                    "ClientAuthentication": {"Sasl": {"Iam": {"Enabled": True}}},
                },
            )
            cluster_arn = resp["ClusterArn"]
            print(f"  Created serverless cluster: {cluster_arn}")
            print("  (Cluster will take a few minutes to become ACTIVE)")
        except ClientError as e:
            print(f"  Cluster creation error: {e}")
            return
    # Attach cluster policy (for multi-VPC private connectivity)
    try:
        msk_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowCrossAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "kafka:CreateVpcConnection",
                    "kafka:GetBootstrapBrokers",
                    "kafka:DescribeCluster",
                    "kafka:DescribeClusterV2",
                ],
                "Resource": cluster_arn,
            }]
        })
        kafka.put_cluster_policy(ClusterArn=cluster_arn, Policy=msk_policy)
        print("  Attached cluster policy")
    except ClientError as e:
        print(f"  Skipped policy (cluster may still be creating): {e}")


def setup_signer(session, region, account_id, role_arn):
    """Create a Signer signing profile with cross-account permissions."""
    print("=== Signer ===")
    signer = session.client("signer", region_name=region)
    profile_name = PREFIX.replace("-", "")  # Signer doesn't allow hyphens
    try:
        signer.put_signing_profile(
            profileName=profile_name,
            platformId="AWSLambda-SHA384-ECDSA",
        )
        print(f"  Created signing profile: {profile_name}")
    except ClientError as e:
        print(f"  Profile exists or error: {e}")
    try:
        signer.add_profile_permission(
            profileName=profile_name,
            action="signer:StartSigningJob",
            principal=account_id,
            statementId="AllowIdentityCenterRole",
        )
        print("  Added profile permission")
    except ClientError as e:
        if "ConflictException" in str(type(e).__name__) or "ConflictException" in str(e):
            print("  Permission already exists")
        else:
            print(f"  Skipped permission: {e}")


def setup_vpc_lattice(session, region, account_id, role_arn):
    """Create a VPC Lattice service with an auth policy."""
    print("=== VPC Lattice ===")
    lattice = session.client("vpc-lattice", region_name=region)
    svc_arn = None
    # Check for existing service
    try:
        services = lattice.list_services()
        for s in services.get("items", []):
            if s.get("name", "") == PREFIX:
                svc_arn = s["arn"]
                print(f"  Reusing existing service: {svc_arn}")
                break
    except ClientError as e:
        print(f"  List error: {e}")
    if not svc_arn:
        try:
            resp = lattice.create_service(name=PREFIX, authType="AWS_IAM")
            svc_arn = resp["arn"]
            print(f"  Created service: {svc_arn}")
        except ClientError as e:
            print(f"  Service creation error: {e}")
            return
    # Attach auth policy
    try:
        lattice.put_auth_policy(
            resourceIdentifier=svc_arn,
            policy=policy_doc(role_arn, "vpc-lattice-svcs:Invoke", svc_arn),
        )
        print("  Attached auth policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


def setup_network_firewall(session, region, account_id, role_arn):
    """Create a Network Firewall rule group with a resource policy."""
    print("=== Network Firewall ===")
    nfw = session.client("network-firewall", region_name=region)
    rg_arn = None
    # Check for existing rule group
    try:
        rgs = nfw.list_rule_groups()
        for rg in rgs.get("RuleGroups", []):
            if PREFIX in rg.get("Name", ""):
                rg_arn = rg["Arn"]
                print(f"  Reusing existing rule group: {rg_arn}")
                break
    except ClientError as e:
        print(f"  List error: {e}")
    if not rg_arn:
        try:
            resp = nfw.create_rule_group(
                RuleGroupName=PREFIX,
                Type="STATELESS",
                Capacity=10,
                RuleGroup={
                    "RulesSource": {
                        "StatelessRulesAndCustomActions": {
                            "StatelessRules": [{
                                "RuleDefinition": {
                                    "MatchAttributes": {
                                        "Sources": [{"AddressDefinition": "0.0.0.0/0"}],
                                        "Destinations": [{"AddressDefinition": "0.0.0.0/0"}],
                                    },
                                    "Actions": ["aws:pass"],
                                },
                                "Priority": 1,
                            }],
                            "CustomActions": [],
                        }
                    }
                },
            )
            rg_arn = resp["RuleGroupResponse"]["RuleGroupArn"]
            print(f"  Created rule group: {rg_arn}")
        except ClientError as e:
            print(f"  Rule group creation error: {e}")
            return
    # Attach resource policy (for cross-account sharing via RAM)
    try:
        nfw_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowCrossAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": [
                    "network-firewall:CreateFirewallPolicy",
                    "network-firewall:UpdateFirewallPolicy",
                    "network-firewall:ListRuleGroups",
                ],
                "Resource": rg_arn,
            }]
        })
        nfw.put_resource_policy(
            ResourceArn=rg_arn,
            Policy=nfw_policy,
        )
        print("  Attached resource policy")
    except ClientError as e:
        print(f"  Skipped policy: {e}")


# ─── S3 Express (Directory Bucket) ───────────────────────────────────────────

def setup_s3_express(session, region, account_id, role_arn):
    """Create an S3 Express directory bucket with a bucket policy."""
    print("=== S3 Express (Directory Bucket) ===")
    s3 = session.client("s3", region_name=region)
    # Directory bucket names: <base>--<az-id>--x-s3
    ec2 = session.client("ec2", region_name=region)
    azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}])
    if not azs["AvailabilityZones"]:
        print("  No AZs available, skipping")
        return
    az_id = azs["AvailabilityZones"][0]["ZoneId"]  # e.g. "usw2-az1"
    bucket_name = f"policy-scan-test--{az_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": az_id},
                "Bucket": {"Type": "Directory", "DataRedundancy": "SingleAvailabilityZone"},
            },
        )
        print(f"  Created directory bucket: {bucket_name}")
    except ClientError as e:
        if "BucketAlreadyOwnedByYou" in str(e) or "BucketAlreadyExists" in str(e):
            print(f"  Directory bucket already exists: {bucket_name}")
        else:
            print(f"  Error creating directory bucket: {e}")
            return

    # Attach policy
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "s3express:CreateSession",
            "Resource": f"arn:aws:s3express:{region}:{account_id}:bucket/{bucket_name}",
        }],
    })
    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=policy)
        print(f"  Attached policy to {bucket_name}")
    except ClientError as e:
        print(f"  Error attaching policy: {e}")


# ─── S3 Tables ────────────────────────────────────────────────────────────────

def setup_s3_tables(session, region, account_id, role_arn):
    """Create an S3 Tables table bucket with a resource policy."""
    print("=== S3 Tables ===")
    try:
        s3tables = session.client("s3tables", region_name=region)
    except Exception as e:
        print(f"  S3 Tables client not available: {e}")
        return

    bucket_name = "policy-scan-test-tables"
    bucket_arn = None
    try:
        resp = s3tables.create_table_bucket(name=bucket_name)
        bucket_arn = resp["arn"]
        print(f"  Created table bucket: {bucket_arn}")
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            # List to find existing ARN
            try:
                buckets = s3tables.list_table_buckets()
                for b in buckets.get("tableBuckets", []):
                    if b["name"] == bucket_name:
                        bucket_arn = b["arn"]
                        break
            except Exception:
                pass
            print(f"  Table bucket already exists: {bucket_arn or bucket_name}")
        else:
            print(f"  Error creating table bucket: {e}")
            return

    if not bucket_arn:
        return

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3tables:*",
            "Resource": bucket_arn,
            "Condition": {"ArnEquals": {"aws:PrincipalArn": role_arn}},
        }],
    })
    try:
        s3tables.put_table_bucket_policy(tableBucketARN=bucket_arn, resourcePolicy=policy)
        print(f"  Attached policy to table bucket")
    except ClientError as e:
        print(f"  Error attaching policy: {e}")


# ─── Redshift Serverless ──────────────────────────────────────────────────────

def setup_redshift_serverless(session, region, account_id, role_arn):
    """Create a Redshift Serverless namespace + snapshot with a resource policy.
    NOTE: This creates a namespace and workgroup (which incurs cost while running).
    The workgroup is created with minimal RPU. A snapshot is taken and the policy
    is attached to the snapshot."""
    print("=== Redshift Serverless ===")
    rs = session.client("redshift-serverless", region_name=region)

    ns_name = "policy-scan-test-ns"
    wg_name = "policy-scan-test-wg"
    snapshot_name = "policy-scan-test-snap"

    # Create namespace
    try:
        rs.create_namespace(namespaceName=ns_name)
        print(f"  Created namespace: {ns_name}")
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            print(f"  Namespace already exists: {ns_name}")
        else:
            print(f"  Error creating namespace: {e}")
            return

    # Create workgroup (minimal config)
    try:
        rs.create_workgroup(
            workgroupName=wg_name,
            namespaceName=ns_name,
            baseCapacity=8,  # minimum RPU
        )
        print(f"  Created workgroup: {wg_name} (8 RPU — delete promptly to avoid cost)")
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            print(f"  Workgroup already exists: {wg_name}")
        else:
            print(f"  Error creating workgroup (may need VPC/subnet): {e}")
            # Try to attach policy to namespace directly if workgroup fails
            try:
                ns_resp = rs.get_namespace(namespaceName=ns_name)
                ns_arn = ns_resp["namespace"]["namespaceArn"]
                policy = json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowCrossAccountAccess",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "redshift-serverless:RestoreFromSnapshot",
                        "Resource": ns_arn,
                    }],
                })
                rs.put_resource_policy(resourceArn=ns_arn, policy=policy)
                print(f"  Attached resource policy to namespace ARN")
            except ClientError as e2:
                print(f"  Could not attach policy: {e2}")
            return

    # Create a snapshot and attach policy
    try:
        import time as _time
        ns_resp = rs.get_namespace(namespaceName=ns_name)
        ns_arn = ns_resp["namespace"]["namespaceArn"]
        # Wait for workgroup to become available
        print("  Waiting for workgroup to become available...")
        for _ in range(20):
            try:
                wg_resp = rs.get_workgroup(workgroupName=wg_name)
                if wg_resp["workgroup"]["status"] == "AVAILABLE":
                    break
            except Exception:
                pass
            _time.sleep(15)

        snap_resp = rs.create_snapshot(namespaceName=ns_name, snapshotName=snapshot_name)
        snap_arn = snap_resp["snapshot"]["snapshotArn"]
        print(f"  Created snapshot: {snap_arn}")

        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "AllowCrossAccountAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "redshift-serverless:RestoreFromSnapshot",
                "Resource": snap_arn,
            }],
        })
        rs.put_resource_policy(resourceArn=snap_arn, policy=policy)
        print(f"  Attached resource policy to snapshot")
    except ClientError as e:
        print(f"  Error with snapshot/policy: {e}")


# ─── Serverless Application Repository ────────────────────────────────────────

def setup_serverless_repo(session, region, account_id, role_arn):
    """Create a Serverless Application Repository app with a policy."""
    print("=== Serverless Application Repository ===")
    sar = session.client("serverlessrepo", region_name=region)

    app_name = "policy-scan-test-app"
    app_id = None

    # Simple SAM template — use InlineCode to avoid S3 dependency
    template_body = """AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: Test app for policy scanning
Resources:
  TestFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: index.handler
      Runtime: python3.12
      InlineCode: |
        def handler(event, context):
            return {"statusCode": 200}
"""

    try:
        resp = sar.create_application(
            Author="policy-scan-test",
            Description="Test application for policy scanning",
            Name=app_name,
            SpdxLicenseId="MIT",
            SemanticVersion="1.0.0",
            TemplateBody=template_body,
        )
        app_id = resp["ApplicationId"]
        print(f"  Created application: {app_id}")
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            # Find existing
            try:
                apps = sar.list_applications()
                for app in apps.get("Applications", []):
                    if app.get("Name") == app_name:
                        app_id = app["ApplicationId"]
                        break
            except Exception:
                pass
            print(f"  Application already exists: {app_id or app_name}")
        else:
            print(f"  Error creating application: {e}")
            return

    if not app_id:
        return

    # Attach application policy referencing the role
    try:
        sar.put_application_policy(
            ApplicationId=app_id,
            Statements=[{
                "Actions": ["serverlessrepo:Deploy"],
                "Principals": [account_id],
                "StatementId": "AllowIdentityCenterRole",
            }],
        )
        print(f"  Attached application policy")
    except ClientError as e:
        print(f"  Error attaching policy: {e}")


# ─── Rekognition ──────────────────────────────────────────────────────────────

def setup_rekognition(session, region, account_id, role_arn):
    """Create a Rekognition Custom Labels project with a project policy.
    NOTE: Rekognition Custom Labels is deprecated but the project policy API
    still exists for cross-account model sharing."""
    print("=== Rekognition ===")
    rek = session.client("rekognition", region_name=region)

    project_name = "policy-scan-test"
    project_arn = None
    try:
        resp = rek.create_project(ProjectName=project_name)
        project_arn = resp["ProjectArn"]
        print(f"  Created project: {project_arn}")
    except ClientError as e:
        if "ResourceInUseException" in str(e) or "already exists" in str(e).lower():
            # Find existing
            try:
                projects = rek.describe_projects()
                for p in projects.get("ProjectDescriptions", []):
                    if p["ProjectArn"].endswith(f"project/{project_name}/"):
                        project_arn = p["ProjectArn"]
                        break
                    if project_name in p["ProjectArn"]:
                        project_arn = p["ProjectArn"]
                        break
            except Exception:
                pass
            print(f"  Project already exists: {project_arn or project_name}")
        else:
            print(f"  Error creating project: {e}")
            return

    if not project_arn:
        return

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowIdentityCenterRole",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "rekognition:CopyProjectVersion",
            "Resource": "*",
            "Condition": {"ArnEquals": {"aws:PrincipalArn": role_arn}},
        }],
    })
    try:
        rek.put_project_policy(
            ProjectArn=project_arn,
            PolicyName="policy-scan-test",
            PolicyDocument=policy,
        )
        print(f"  Attached project policy")
    except ClientError as e:
        print(f"  Error attaching policy: {e}")


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

    # MSK
    try:
        kafka = session.client("kafka", region_name=region)
        clusters = kafka.list_clusters_v2()
        for c in clusters.get("ClusterInfoList", []):
            if c.get("ClusterName", "") == PREFIX:
                kafka.delete_cluster(ClusterArn=c["ClusterArn"])
                print(f"  Deleted MSK cluster: {c['ClusterArn']}")
    except ClientError as e:
        print(f"  MSK cleanup: {e}")

    # Signer
    try:
        signer = session.client("signer", region_name=region)
        profile_name = PREFIX.replace("-", "")
        signer.cancel_signing_profile(profileName=profile_name)
        print(f"  Canceled signing profile: {profile_name}")
    except ClientError as e:
        print(f"  Signer cleanup: {e}")

    # VPC Lattice
    try:
        lattice = session.client("vpc-lattice", region_name=region)
        services = lattice.list_services()
        for s in services.get("items", []):
            if s.get("name", "") == PREFIX:
                lattice.delete_service(serviceIdentifier=s["id"])
                print(f"  Deleted VPC Lattice service: {s['id']}")
    except ClientError as e:
        print(f"  VPC Lattice cleanup: {e}")

    # Network Firewall
    try:
        nfw = session.client("network-firewall", region_name=region)
        rgs = nfw.list_rule_groups()
        for rg in rgs.get("RuleGroups", []):
            if PREFIX in rg.get("Name", ""):
                nfw.delete_rule_group(RuleGroupArn=rg["Arn"])
                print(f"  Deleted Network Firewall rule group: {rg['Arn']}")
    except ClientError as e:
        print(f"  Network Firewall cleanup: {e}")

    # S3 Express (Directory Bucket)
    try:
        s3 = session.client("s3", region_name=region)
        ec2 = session.client("ec2", region_name=region)
        azs = ec2.describe_availability_zones(Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}])
        az_id = azs["AvailabilityZones"][0]["ZoneId"] if azs["AvailabilityZones"] else "usw2-az1"
        bucket_name = f"policy-scan-test--{az_id}--x-s3"
        s3.delete_bucket_policy(Bucket=bucket_name)
        s3.delete_bucket(Bucket=bucket_name)
        print(f"  Deleted directory bucket: {bucket_name}")
    except ClientError as e:
        print(f"  S3 Express cleanup: {e}")

    # S3 Tables
    try:
        s3tables = session.client("s3tables", region_name=region)
        buckets = s3tables.list_table_buckets()
        for b in buckets.get("tableBuckets", []):
            if b["name"] == "policy-scan-test-tables":
                s3tables.delete_table_bucket_policy(tableBucketARN=b["arn"])
                s3tables.delete_table_bucket(tableBucketARN=b["arn"])
                print(f"  Deleted table bucket: {b['arn']}")
    except ClientError as e:
        print(f"  S3 Tables cleanup: {e}")

    # Redshift Serverless
    try:
        rs = session.client("redshift-serverless", region_name=region)
        # Delete snapshot first
        try:
            rs.delete_snapshot(snapshotName="policy-scan-test-snap")
            print("  Deleted Redshift Serverless snapshot")
        except ClientError:
            pass
        # Delete workgroup
        try:
            rs.delete_workgroup(workgroupName="policy-scan-test-wg")
            print("  Deleted Redshift Serverless workgroup (may take a moment)")
        except ClientError:
            pass
        # Delete namespace
        try:
            rs.delete_namespace(namespaceName="policy-scan-test-ns")
            print("  Deleted Redshift Serverless namespace")
        except ClientError:
            pass
    except ClientError as e:
        print(f"  Redshift Serverless cleanup: {e}")

    # Serverless Application Repository
    try:
        sar = session.client("serverlessrepo", region_name=region)
        apps = sar.list_applications()
        for app in apps.get("Applications", []):
            if app.get("Name") == "policy-scan-test-app":
                sar.delete_application(ApplicationId=app["ApplicationId"])
                print(f"  Deleted SAR application: {app['ApplicationId']}")
    except ClientError as e:
        print(f"  Serverless App Repo cleanup: {e}")

    # Rekognition
    try:
        rek = session.client("rekognition", region_name=region)
        projects = rek.describe_projects()
        for p in projects.get("ProjectDescriptions", []):
            if "policy-scan-test" in p["ProjectArn"]:
                # Delete policy first
                try:
                    policies = rek.list_project_policies(ProjectArn=p["ProjectArn"])
                    for pol in policies.get("ProjectPolicies", []):
                        rek.delete_project_policy(
                            ProjectArn=p["ProjectArn"],
                            PolicyName=pol["PolicyName"],
                            PolicyRevisionId=pol["PolicyRevisionId"],
                        )
                except Exception:
                    pass
                rek.delete_project(ProjectArn=p["ProjectArn"])
                print(f"  Deleted Rekognition project: {p['ProjectArn']}")
    except ClientError as e:
        print(f"  Rekognition cleanup: {e}")

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
    setup_msk(session, region, account_id, role_arn)
    setup_signer(session, region, account_id, role_arn)
    setup_vpc_lattice(session, region, account_id, role_arn)
    setup_network_firewall(session, region, account_id, role_arn)
    setup_s3_express(session, region, account_id, role_arn)
    setup_s3_tables(session, region, account_id, role_arn)
    setup_redshift_serverless(session, region, account_id, role_arn)
    setup_serverless_repo(session, region, account_id, role_arn)
    setup_rekognition(session, region, account_id, role_arn)

    print("\n" + "=" * 70)
    print("All test resources deployed.")
    print("Run the scanner to verify:")
    print(f'  python3 scan_resource_policies.py --search "{role_arn}" --regions {region}')
    print("\nTo clean up:")
    print(f"  python3 deploy_test_policies.py --region {region} --cleanup")


if __name__ == "__main__":
    main()
