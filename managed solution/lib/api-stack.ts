import * as cdk from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import { Construct } from "constructs";
import * as path from "path";

interface ApiStackProps extends cdk.StackProps {
  jobsTable: dynamodb.Table;
  migrationLogTable: dynamodb.Table;
  resultsBucket: s3.Bucket;
  policyScanStateMachine: sfn.StateMachine;
  iamDiscoverStateMachine: sfn.StateMachine;
  iamMigrateStateMachine: sfn.StateMachine;
  idcDiscoverStateMachine: sfn.StateMachine;
  idcApplyStateMachine: sfn.StateMachine;
  orgId: string;
}

export class ApiStack extends cdk.Stack {
  public readonly api: apigateway.RestApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const lambdaDir = path.join(__dirname, "..", "lambda");

    // ─── Shared utilities Layer ───────────────────────────────────────────
    const sharedLayer = new lambda.LayerVersion(this, "ApiSharedUtilsLayer", {
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "layers", "shared-utils")),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_12],
      description: "Truffle shared utilities for API Lambdas",
    });

    // ─── API Gateway (Regional, IAM Auth) ─────────────────────────────────
    this.api = new apigateway.RestApi(this, "TruffleApi", {
      restApiName: "TruffleApi",
      description: "Truffle managed backend API — IAM authorized",
      endpointTypes: [apigateway.EndpointType.REGIONAL],
      policy: new iam.PolicyDocument({
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            principals: [new iam.AnyPrincipal()],
            actions: ["execute-api:Invoke"],
            resources: ["execute-api:/*"],
            conditions: {
              StringEquals: {
                "aws:PrincipalOrgID": props.orgId,
              },
            },
          }),
          new iam.PolicyStatement({
            effect: iam.Effect.DENY,
            principals: [new iam.AnyPrincipal()],
            actions: ["execute-api:Invoke"],
            resources: ["execute-api:/*"],
            conditions: {
              StringNotEquals: {
                "aws:PrincipalOrgID": props.orgId,
              },
            },
          }),
        ],
      }),
      deployOptions: {
        stageName: "prod",
      },
    });

    const iamAuth: apigateway.MethodOptions = {
      authorizationType: apigateway.AuthorizationType.IAM,
    };

    // ─── Start Job Lambda ─────────────────────────────────────────────────
    const startJobFn = new lambda.Function(this, "StartJobFn", {
      functionName: "TruffleStartJob",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "start-job")),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      layers: [sharedLayer],
      environment: {
        JOBS_TABLE: props.jobsTable.tableName,
        RESULTS_BUCKET: props.resultsBucket.bucketName,
        POLICY_SCAN_SM_ARN: props.policyScanStateMachine.stateMachineArn,
        IAM_DISCOVER_SM_ARN: props.iamDiscoverStateMachine.stateMachineArn,
        IAM_MIGRATE_SM_ARN: props.iamMigrateStateMachine.stateMachineArn,
        IDC_DISCOVER_SM_ARN: props.idcDiscoverStateMachine.stateMachineArn,
        IDC_APPLY_SM_ARN: props.idcApplyStateMachine.stateMachineArn,
      },
    });

    props.jobsTable.grantReadWriteData(startJobFn);
    props.resultsBucket.grantRead(startJobFn);
    props.policyScanStateMachine.grantStartExecution(startJobFn);
    props.iamDiscoverStateMachine.grantStartExecution(startJobFn);
    props.iamMigrateStateMachine.grantStartExecution(startJobFn);
    props.idcDiscoverStateMachine.grantStartExecution(startJobFn);
    props.idcApplyStateMachine.grantStartExecution(startJobFn);

    // ─── Get Status Lambda ────────────────────────────────────────────────
    const getStatusFn = new lambda.Function(this, "GetStatusFn", {
      functionName: "TruffleGetStatus",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "get-status")),
      memorySize: 128,
      timeout: cdk.Duration.seconds(10),
      layers: [sharedLayer],
      environment: {
        JOBS_TABLE: props.jobsTable.tableName,
        POLICY_SCAN_SM_ARN: props.policyScanStateMachine.stateMachineArn,
        IAM_DISCOVER_SM_ARN: props.iamDiscoverStateMachine.stateMachineArn,
        IAM_MIGRATE_SM_ARN: props.iamMigrateStateMachine.stateMachineArn,
      },
    });

    props.jobsTable.grantReadData(getStatusFn);
    // Allow listing executions for stale job detection
    props.policyScanStateMachine.grantRead(getStatusFn);
    props.iamDiscoverStateMachine.grantRead(getStatusFn);
    props.iamMigrateStateMachine.grantRead(getStatusFn);

    // ─── Get Result Lambda ────────────────────────────────────────────────
    const getResultFn = new lambda.Function(this, "GetResultFn", {
      functionName: "TruffleGetResult",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "get-result")),
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      layers: [sharedLayer],
      environment: {
        JOBS_TABLE: props.jobsTable.tableName,
        RESULTS_BUCKET: props.resultsBucket.bucketName,
      },
    });

    props.jobsTable.grantReadData(getResultFn);
    props.resultsBucket.grantRead(getResultFn);

    // ─── API Routes ───────────────────────────────────────────────────────
    const api_resource = this.api.root.addResource("api");

    // Policy Analysis
    const policyAnalysis = api_resource.addResource("policy-analysis");
    const policyScan = policyAnalysis.addResource("scan");
    policyScan.addMethod("POST", new apigateway.LambdaIntegration(startJobFn), iamAuth);

    const policyStatus = policyAnalysis.addResource("status");
    policyStatus.addMethod("GET", new apigateway.LambdaIntegration(getStatusFn), iamAuth);

    const policyResult = policyAnalysis.addResource("result");
    policyResult.addMethod("GET", new apigateway.LambdaIntegration(getResultFn), iamAuth);

    // IAM Federation
    const iamFederation = api_resource.addResource("iam-federation");

    const iamDiscover = iamFederation.addResource("discover");
    iamDiscover.addMethod("POST", new apigateway.LambdaIntegration(startJobFn), iamAuth);

    const iamDiscoverStatus = iamDiscover.addResource("status");
    iamDiscoverStatus.addMethod("GET", new apigateway.LambdaIntegration(getStatusFn), iamAuth);

    const iamDiscoverResult = iamDiscover.addResource("result");
    iamDiscoverResult.addMethod("GET", new apigateway.LambdaIntegration(getResultFn), iamAuth);

    const iamMigrate = iamFederation.addResource("migrate");
    iamMigrate.addMethod("POST", new apigateway.LambdaIntegration(startJobFn), iamAuth);

    const iamMigrateStatus = iamMigrate.addResource("status");
    iamMigrateStatus.addMethod("GET", new apigateway.LambdaIntegration(getStatusFn), iamAuth);

    // IdC
    const idc = api_resource.addResource("idc");

    const idcDiscover = idc.addResource("discover");
    idcDiscover.addMethod("POST", new apigateway.LambdaIntegration(startJobFn), iamAuth);

    const idcDiscoverStatus = idcDiscover.addResource("status");
    idcDiscoverStatus.addMethod("GET", new apigateway.LambdaIntegration(getStatusFn), iamAuth);

    const idcDiscoverResult = idcDiscover.addResource("result");
    idcDiscoverResult.addMethod("GET", new apigateway.LambdaIntegration(getResultFn), iamAuth);

    const idcApply = idc.addResource("apply");
    idcApply.addMethod("POST", new apigateway.LambdaIntegration(startJobFn), iamAuth);

    const idcApplyStatus = idcApply.addResource("status");
    idcApplyStatus.addMethod("GET", new apigateway.LambdaIntegration(getStatusFn), iamAuth);

    const idcApplyResult = idcApply.addResource("result");
    idcApplyResult.addMethod("GET", new apigateway.LambdaIntegration(getResultFn), iamAuth);

    // ─── Outputs ──────────────────────────────────────────────────────────
    new cdk.CfnOutput(this, "ApiEndpoint", {
      value: this.api.url,
      description: "Truffle API endpoint (set as TRUFFLE_API_ENDPOINT)",
    });

    new cdk.CfnOutput(this, "ApiId", {
      value: this.api.restApiId,
      description: "API Gateway REST API ID",
    });
  }
}
