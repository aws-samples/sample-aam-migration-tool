import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";

export class StorageStack extends cdk.Stack {
  public readonly jobsTable: dynamodb.Table;
  public readonly migrationLogTable: dynamodb.Table;
  public readonly resultsBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // ─── Jobs table ───────────────────────────────────────────────────────
    this.jobsTable = new dynamodb.Table(this, "JobsTable", {
      tableName: "TruffleJobs",
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: "TTL",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ─── Migration log table ──────────────────────────────────────────────
    this.migrationLogTable = new dynamodb.Table(this, "MigrationLogTable", {
      tableName: "TruffleMigrationLog",
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: "TTL",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // ─── Results bucket ───────────────────────────────────────────────────
    this.resultsBucket = new s3.Bucket(this, "ResultsBucket", {
      bucketName: `truffle-results-${cdk.Aws.ACCOUNT_ID}`,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      lifecycleRules: [
        {
          expiration: cdk.Duration.days(90),
          prefix: "callers/",
        },
      ],
    });
  }
}
