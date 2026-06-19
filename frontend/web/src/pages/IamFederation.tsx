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

// SKELETON: this page lays out the intended IAM Federation -> AAM workflow.
// Inputs render but no migration is performed yet.
export default function IamFederation() {
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
            <Header variant="h2" description="Step 2 — select which federated roles to migrate.">
              Federated roles
            </Header>
          }
        >
          <Table
            variant="embedded"
            selectionType="multi"
            items={[]}
            trackBy="arn"
            empty={<Box textAlign="center">Import entitlements to populate roles.</Box>}
            columnDefinitions={[
              { id: "role", header: "Role", cell: () => "" },
              { id: "arn", header: "ARN", cell: () => "" },
              { id: "accounts", header: "Account(s)", cell: () => "" },
              { id: "groups", header: "Mapped groups", cell: () => "" },
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
