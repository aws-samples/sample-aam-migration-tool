import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import { Construct } from "constructs";
import * as path from "path";

interface WorkflowStackProps extends cdk.StackProps {
  jobsTable: dynamodb.Table;
  migrationLogTable: dynamodb.Table;
  resultsBucket: s3.Bucket;
  externalId: string;
}

export class WorkflowStack extends cdk.Stack {
  public readonly policyScanStateMachine: sfn.StateMachine;
  public readonly iamDiscoverStateMachine: sfn.StateMachine;
  public readonly iamMigrateStateMachine: sfn.StateMachine;

  constructor(scope: Construct, id: string, props: WorkflowStackProps) {
    super(scope, id, props);

    const lambdaDir = path.join(__dirname, "..", "lambda");

    // ─── Custom boto3 Layer (preview SDK with AAM service model) ──────────
    const customBoto3Layer = new lambda.LayerVersion(this, "CustomBoto3Layer", {
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "layers", "custom-boto3")),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_12],
      description: "Custom boto3/botocore with AAM (accountaccess) service model",
    });

    // ─── Shared Lambda execution role ─────────────────────────────────────
    const lambdaExecRole = new iam.Role(this, "TruffleLambdaExecRole", {
      roleName: "TruffleLambdaExecRole",
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"),
      ],
    });

    // Allow assuming TruffleRole in any account (scoped by external ID at runtime)
    lambdaExecRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["sts:AssumeRole"],
        resources: ["arn:aws:iam::*:role/TruffleRole"],
      })
    );

    // DynamoDB access
    props.jobsTable.grantReadWriteData(lambdaExecRole);
    props.migrationLogTable.grantReadWriteData(lambdaExecRole);

    // S3 results access
    props.resultsBucket.grantReadWrite(lambdaExecRole);

    // ─── Scan Unit Lambda ─────────────────────────────────────────────────
    const scanUnitFn = new lambda.Function(this, "ScanUnitFn", {
      functionName: "TruffleScanUnit",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "scan-unit")),
      role: lambdaExecRole,
      memorySize: 512,
      timeout: cdk.Duration.minutes(5),
      environment: {
        EXTERNAL_ID: props.externalId,
        RESULTS_BUCKET: props.resultsBucket.bucketName,
      },
    });

    // ─── Scan Global Lambda ───────────────────────────────────────────────
    const scanGlobalFn = new lambda.Function(this, "ScanGlobalFn", {
      functionName: "TruffleScanGlobal",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "scan-global")),
      role: lambdaExecRole,
      memorySize: 512,
      timeout: cdk.Duration.minutes(10),
      environment: {
        EXTERNAL_ID: props.externalId,
        RESULTS_BUCKET: props.resultsBucket.bucketName,
      },
    });

    // ─── Discover Roles Lambda ────────────────────────────────────────────
    const discoverRolesFn = new lambda.Function(this, "DiscoverRolesFn", {
      functionName: "TruffleDiscoverRoles",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "discover-roles")),
      role: lambdaExecRole,
      memorySize: 1024,
      timeout: cdk.Duration.minutes(10),
      layers: [customBoto3Layer],
      environment: {
        EXTERNAL_ID: props.externalId,
      },
    });

    // ─── Migrate Role Lambda ──────────────────────────────────────────────
    const migrateRoleFn = new lambda.Function(this, "MigrateRoleFn", {
      functionName: "TruffleMigrateRole",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "migrate-role")),
      role: lambdaExecRole,
      memorySize: 256,
      timeout: cdk.Duration.seconds(30),
      layers: [customBoto3Layer],
      environment: {
        EXTERNAL_ID: props.externalId,
        MIGRATION_LOG_TABLE: props.migrationLogTable.tableName,
      },
    });

    // ─── Aggregate Lambda ─────────────────────────────────────────────────
    const aggregateFn = new lambda.Function(this, "AggregateFn", {
      functionName: "TruffleAggregate",
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "handler.lambda_handler",
      code: lambda.Code.fromAsset(path.join(lambdaDir, "aggregate")),
      role: lambdaExecRole,
      memorySize: 1024,
      timeout: cdk.Duration.minutes(2),
      environment: {
        RESULTS_BUCKET: props.resultsBucket.bucketName,
        JOBS_TABLE: props.jobsTable.tableName,
      },
    });

    // ─── Step Functions: Policy Scan ──────────────────────────────────────
    this.policyScanStateMachine = new sfn.StateMachine(this, "PolicyScanSM", {
      stateMachineName: "TrufflePolicyScan",
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromFile(
        path.join(__dirname, "..", "state-machines", "policy-scan.asl.json")
      ),
      definitionSubstitutions: {
        ScanUnitFnArn: scanUnitFn.functionArn,
        ScanGlobalFnArn: scanGlobalFn.functionArn,
        AggregateFnArn: aggregateFn.functionArn,
        JobsTableName: props.jobsTable.tableName,
      },
    });

    scanUnitFn.grantInvoke(this.policyScanStateMachine);
    scanGlobalFn.grantInvoke(this.policyScanStateMachine);
    aggregateFn.grantInvoke(this.policyScanStateMachine);
    props.jobsTable.grantReadWriteData(this.policyScanStateMachine);

    // ─── Step Functions: IAM Discover ─────────────────────────────────────
    this.iamDiscoverStateMachine = new sfn.StateMachine(this, "IamDiscoverSM", {
      stateMachineName: "TruffleIamDiscover",
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromFile(
        path.join(__dirname, "..", "state-machines", "iam-discover.asl.json")
      ),
      definitionSubstitutions: {
        DiscoverRolesFnArn: discoverRolesFn.functionArn,
        AggregateFnArn: aggregateFn.functionArn,
        JobsTableName: props.jobsTable.tableName,
      },
    });

    discoverRolesFn.grantInvoke(this.iamDiscoverStateMachine);
    aggregateFn.grantInvoke(this.iamDiscoverStateMachine);
    props.jobsTable.grantReadWriteData(this.iamDiscoverStateMachine);

    // ─── Step Functions: IAM Migrate ──────────────────────────────────────
    this.iamMigrateStateMachine = new sfn.StateMachine(this, "IamMigrateSM", {
      stateMachineName: "TruffleIamMigrate",
      stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromFile(
        path.join(__dirname, "..", "state-machines", "iam-migrate.asl.json")
      ),
      definitionSubstitutions: {
        MigrateRoleFnArn: migrateRoleFn.functionArn,
        AggregateFnArn: aggregateFn.functionArn,
        JobsTableName: props.jobsTable.tableName,
        MigrationLogTableName: props.migrationLogTable.tableName,
      },
    });

    migrateRoleFn.grantInvoke(this.iamMigrateStateMachine);
    aggregateFn.grantInvoke(this.iamMigrateStateMachine);
    props.jobsTable.grantReadWriteData(this.iamMigrateStateMachine);
    props.migrationLogTable.grantReadWriteData(this.iamMigrateStateMachine);
  }
}
