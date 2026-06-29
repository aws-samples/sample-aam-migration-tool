import { useState } from "react";
import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import Textarea from "@cloudscape-design/components/textarea";
import { AuthMethodSelect, INITIAL_AUTH_STATE, type AuthState } from "../components/AuthMethodSelect";
import { exportToCsv } from "../utils/csv";

// SKELETON: this page lays out the intended IAM Federation -> AAM workflow.
// Inputs render but no migration is performed yet.
export default function IamFederation() {
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);

  // Placeholder items — populated once entitlement import is implemented.
  const roles: { arn: string; role: string; accounts: string; groups: string }[] = [];

  function handleExport() {
    if (!roles.length) return;
    exportToCsv("iam_federation_roles.csv", roles, [
      { key: "role", header: "Role" },
      { key: "arn", header: "ARN" },
      { key: "accounts", header: "Account(s)" },
      { key: "groups", header: "Mapped groups" },
    ]);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Migrate SAML federated roles to AAM by adding the AAM service principal to their trust policies."
        >
          IAM Federation → AAM
        </Header>
      }
    >
      <SpaceBetween size="l">
        <Alert type="info" header="Skeleton">
          This workflow is an outline. Entitlement import, role discovery, and trust-policy
          migration are not implemented yet.
        </Alert>

        <Container header={<Header variant="h2">Credentials</Header>}>
          <AuthMethodSelect state={auth} onChange={setAuth} profileMode="multi" />
        </Container>

        {/* Step 1 — provide entitlements/assignments */}
        <Container
          header={
            <Header variant="h2" description="Step 1 — provide the entitlements/assignments for the account(s) being migrated.">
              Input entitlements
            </Header>
          }
        >
          <SpaceBetween size="m">
            <FormField label="Entitlements / assignments (JSON)">
              <Textarea
                value=""
                onChange={() => {}}
                placeholder='{ "assignments": [ ... ] }'
                rows={8}
                disabled
              />
            </FormField>
            <Button disabled>Import entitlements</Button>
          </SpaceBetween>
        </Container>

        {/* Step 2 — select federated roles to migrate */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 2 — select which federated roles to migrate."
              actions={
                <Button iconName="download" onClick={handleExport} disabled={!roles.length}>
                  Export CSV
                </Button>
              }
            >
              Federated roles
            </Header>
          }
        >
          <Table
            variant="embedded"
            resizableColumns
            selectionType="multi"
            items={roles}
            trackBy="arn"
            empty={<Box textAlign="center">Import entitlements to populate roles.</Box>}
            columnDefinitions={[
              { id: "role", header: "Role", cell: (r) => r.role, minWidth: 150 },
              { id: "arn", header: "ARN", cell: (r) => r.arn, minWidth: 200 },
              { id: "accounts", header: "Account(s)", cell: (r) => r.accounts, minWidth: 120 },
              { id: "groups", header: "Mapped groups", cell: (r) => r.groups, minWidth: 150 },
            ]}
          />
        </Container>

        {/* Step 3 — migrate */}
        <Container
          header={
            <Header variant="h2" description="Step 3 — update trust policies to add sts:AssumeRole for the AAM service principal. Results are logged per role.">
              Migrate
            </Header>
          }
        >
          <Button variant="primary" disabled>
            Migrate selected roles
          </Button>
        </Container>
      </SpaceBetween>
    </ContentLayout>
  );
}
