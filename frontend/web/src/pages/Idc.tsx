import { useState } from "react";
import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import { AuthMethodSelect, INITIAL_AUTH_STATE, parseAccountIds, type AuthState } from "../components/AuthMethodSelect";
import { exportToCsv } from "../utils/csv";

// SKELETON: this page lays out the intended IdC -> AAM workflow.
// Discovery and CloudFormation generation are not implemented yet.
export default function Idc() {
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);

  // Placeholder items — populated once discovery is implemented.
  const permissionSets: { id: string; account: string; permissionSet: string; policies: string; assignments: string }[] = [];

  // The "Run discovery" button requires at least one credential source.
  const canDiscover =
    auth.operatingMode === "single"
      ? true
      : auth.authMethod === "profiles"
        ? !!auth.singleProfile
        : parseAccountIds(auth.accountIds).length > 0 && !!auth.roleName.trim();

  function handleExport() {
    if (!permissionSets.length) return;
    exportToCsv("idc_permission_sets.csv", permissionSets, [
      { key: "account", header: "Account" },
      { key: "permissionSet", header: "Permission set" },
      { key: "policies", header: "Policies (inline / managed / CMP)" },
      { key: "assignments", header: "Assignments" },
    ]);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Inventory IdC permission sets and assignments, then generate a CloudFormation template of equivalent IAM roles."
        >
          IdC → AAM
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Alert type="info" header="Skeleton">
          This workflow is an outline. Discovery and CloudFormation generation are not
          implemented yet.
        </Alert>

        <Container
          header={
            <Header variant="h2" description="Credentials for the IdC management or delegated admin account.">
              Credentials
            </Header>
          }
        >
          <AuthMethodSelect state={auth} onChange={setAuth} profileMode="single" />
        </Container>

        {/* Step 1 — run discovery */}
        <Container
          header={
            <Header variant="h2" description="Step 1 — run discovery against the IdC management / delegated-admin account.">
              Discovery
            </Header>
          }
        >
          <Button variant="primary" disabled={!canDiscover}>
            Run discovery
          </Button>
        </Container>

        {/* Step 2 — select permission sets / assignments by account */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 2 — select permission sets and assignments to migrate, organized by account."
              actions={
                <Button iconName="download" onClick={handleExport} disabled={!permissionSets.length}>
                  Export CSV
                </Button>
              }
            >
              Permission sets &amp; assignments
            </Header>
          }
        >
          <Table
            variant="embedded"
            resizableColumns
            selectionType="multi"
            items={permissionSets}
            trackBy="id"
            empty={<Box textAlign="center">Run discovery to populate permission sets.</Box>}
            columnDefinitions={[
              { id: "account", header: "Account", cell: (r) => r.account, minWidth: 120 },
              { id: "permissionSet", header: "Permission set", cell: (r) => r.permissionSet, minWidth: 150 },
              { id: "policies", header: "Policies (inline / managed / CMP)", cell: (r) => r.policies, minWidth: 200 },
              { id: "assignments", header: "Assignments", cell: (r) => r.assignments, minWidth: 150 },
            ]}
          />
        </Container>

        {/* Step 3 — generate CloudFormation */}
        <Container
          header={
            <Header variant="h2" description="Step 3 — generate a CloudFormation template with the IAM roles to create.">
              Generate CloudFormation
            </Header>
          }
        >
          <Button variant="primary" disabled>
            Generate template
          </Button>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
