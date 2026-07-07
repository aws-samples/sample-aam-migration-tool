#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { StorageStack } from "../lib/storage-stack";
import { WorkflowStack } from "../lib/workflow-stack";
import { ApiStack } from "../lib/api-stack";

const app = new cdk.App();

const orgId = app.node.tryGetContext("orgId") || "o-xxxxxxxxxx";
const externalId = app.node.tryGetContext("externalId") || "truffle-default-external-id";

const storage = new StorageStack(app, "TruffleStorageStack", {
  description: "Truffle managed backend — DynamoDB + S3 storage",
});

const workflows = new WorkflowStack(app, "TruffleWorkflowStack", {
  description: "Truffle managed backend — Step Functions workflows",
  jobsTable: storage.jobsTable,
  migrationLogTable: storage.migrationLogTable,
  resultsBucket: storage.resultsBucket,
  externalId,
});

new ApiStack(app, "TruffleApiStack", {
  description: "Truffle managed backend — API Gateway + Lambda",
  jobsTable: storage.jobsTable,
  migrationLogTable: storage.migrationLogTable,
  resultsBucket: storage.resultsBucket,
  policyScanStateMachine: workflows.policyScanStateMachine,
  iamDiscoverStateMachine: workflows.iamDiscoverStateMachine,
  iamMigrateStateMachine: workflows.iamMigrateStateMachine,
  orgId,
});
