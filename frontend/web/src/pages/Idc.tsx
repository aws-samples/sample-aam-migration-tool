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
import { ProfileSingleSelect, type SelectOption } from "../components/ProfileSelect";

// SKELETON: this page lays out the intended IdC -> AAM workflow.
// Discovery and CloudFormation generation are not implemented yet.
export default function Idc() {
  const [profile, setProfile] = useState<SelectOption | null>(null);

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

        <Alert type="warning" header="Credentials">
          You MUST supply a credential profile for the IdC <b>management</b> or{" "}
          <b>delegated admin</b> account.
        </Alert>

        {/* Step 1 — supply profile + run discovery */}
        <Container
          header={
            <Header variant="h2" description="Step 1 — supply the management / delegated-admin profile and run discovery.">
              Discovery
            </Header>
          }
        >
          <SpaceBetween size="m">
            <FormField label="IdC management / delegated-admin profile">
              <ProfileSingleSelect selected={profile} onChange={setProfile} />
            </FormField>
            <Button variant="primary" disabled={!profile}>
              Run discovery
            </Button>
          </SpaceBetween>
        </Container>

        {/* Step 2 — select permission sets / assignments by account */}
        <Container
          header={
            <Header variant="h2" description="Step 2 — select permission sets and assignments to migrate, organized by account.">
              Permission sets &amp; assignments
            </Header>
          }
        >
          <Table
            variant="embedded"
            selectionType="multi"
            items={[]}
            trackBy="id"
            empty={<Box textAlign="center">Run discovery to populate permission sets.</Box>}
            columnDefinitions={[
              { id: "account", header: "Account", cell: () => "" },
              { id: "permissionSet", header: "Permission set", cell: () => "" },
              { id: "policies", header: "Policies (inline / managed / CMP)", cell: () => "" },
              { id: "assignments", header: "Assignments", cell: () => "" },
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
