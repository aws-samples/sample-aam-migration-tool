import { useEffect, useRef, useState } from "react";
import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import Modal from "@cloudscape-design/components/modal";
import ProgressBar from "@cloudscape-design/components/progress-bar";
import RadioGroup from "@cloudscape-design/components/radio-group";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Table from "@cloudscape-design/components/table";
import Textarea from "@cloudscape-design/components/textarea";
import { api, type CacheWrapper, type JobProgress } from "../api/client";
import { AuthMethodSelect, INITIAL_AUTH_STATE, parseAccountIds, type AuthState } from "../components/AuthMethodSelect";
import { exportToCsv } from "../utils/csv";
import { formatAbsolute, formatAge } from "../utils/time";

interface Provider {
  arn: string;
  name: string;
  account_id: string;
  label: string;
  is_identity_center: boolean;
}

interface RolePolicy {
  policy_name: string;
  policy_type: string;
  policy_arn?: string;
}

interface FederatedRole {
  role_name: string;
  role_arn: string;
  account_id: string;
  label: string;
  trust_summary: string;
  policies: RolePolicy[];
  error?: string;
}

interface MigrateResult {
  role_arn: string;
  role_name: string;
  status: "success" | "skipped" | "error";
  error?: string;
  reason?: string;
  mode?: string;
  timestamp?: string;
}

const POLL_MS = 1000;
const DISCOVER_JOB_KEY = "truffle.iamDiscoverJob";

type MigrateMode = "ADD" | "REPLACE";

export default function IamFederation() {
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);
  const [error, setError] = useState<string | null>(null);

  // Step 1: Providers
  const [providers, setProviders] = useState<Provider[]>([]);
  const [loadingProviders, setLoadingProviders] = useState(false);
  const [selectedIdp, setSelectedIdp] = useState<string>("");

  // Step 2: Discovery
  const [discovering, setDiscovering] = useState(false);
  const [discoverProgress, setDiscoverProgress] = useState<JobProgress | null>(null);
  const [roles, setRoles] = useState<FederatedRole[]>([]);
  const [cachedAt, setCachedAt] = useState<string | undefined>();
  const [selectedRoles, setSelectedRoles] = useState<FederatedRole[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Step 3: Entitlement mapping
  const [groupPattern, setGroupPattern] = useState("{principal}_{account}_{role}");
  const [groupNamesRaw, setGroupNamesRaw] = useState("");
  const [entitlementMappings, setEntitlementMappings] = useState<{ group: string; principal: string; account: string; role: string; matchedRoleArn: string; matchedRoleName: string }[]>([]);

  // Step 4: Migrate
  const [migrateMode, setMigrateMode] = useState<MigrateMode>("ADD");
  const [migrating, setMigrating] = useState(false);
  const [migrateResults, setMigrateResults] = useState<MigrateResult[]>([]);

  // Step 4: IaC
  const [iacLoading, setIacLoading] = useState(false);
  const [iacResult, setIacResult] = useState<{ cloudformation: { content: string; path: string }; terraform: { content: string; path: string } } | null>(null);
  const [iacModal, setIacModal] = useState<"cloudformation" | "terraform" | null>(null);

  // Load cached state on mount
  useEffect(() => {
    api.iamState().then((r: CacheWrapper) => {
      if (r?.data) {
        const data = r.data as { roles?: FederatedRole[]; idp_arn?: string };
        if (data.roles) setRoles(data.roles.filter((r) => !r.error));
        if (data.idp_arn) setSelectedIdp(data.idp_arn);
        setCachedAt(r.cached_at);
      }
    });
    // Re-attach to a running discovery job
    const saved = localStorage.getItem(DISCOVER_JOB_KEY);
    if (saved) {
      setDiscovering(true);
      setDiscoverProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "reconnecting…" });
      startPolling(saved, true);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ─── Auth payload helper ────────────────────────────────────────────────────
  function authPayload(): Record<string, unknown> {
    if (auth.operatingMode === "single") {
      return { auth_method: "profiles" };
    }
    if (auth.authMethod === "assume_role") {
      return {
        auth_method: "assume_role",
        account_ids: parseAccountIds(auth.accountIds),
        role_name: auth.roleName.trim(),
      };
    }
    return { auth_method: "profiles", profiles: auth.profiles.map((p) => p.value) };
  }

  // ─── Step 1: List providers ─────────────────────────────────────────────────
  async function loadProviders() {
    setLoadingProviders(true);
    setError(null);
    try {
      const res = await api.iamProviders(authPayload());
      setProviders(res.providers);
      // Auto-select the first non-IDC provider if there's only one
      const nonIdc = res.providers.filter((p) => !p.is_identity_center);
      if (nonIdc.length === 1) setSelectedIdp(nonIdc[0].arn);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoadingProviders(false);
    }
  }

  // ─── Step 2: Discover roles ─────────────────────────────────────────────────
  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function tick(jobId: string, isReattach: boolean) {
    try {
      const job = await api.iamDiscoverStatus(jobId);
      setDiscoverProgress(job.progress);
      if (job.status === "done" && job.result?.data) {
        stopPolling(); localStorage.removeItem(DISCOVER_JOB_KEY);
        const data = job.result.data as { roles?: FederatedRole[] };
        setRoles((data.roles || []).filter((r) => !r.error));
        setCachedAt(job.result.cached_at);
        setDiscovering(false);
      } else if (job.status === "error") {
        stopPolling(); localStorage.removeItem(DISCOVER_JOB_KEY);
        setError(job.error || "Discovery failed"); setDiscovering(false);
      }
    } catch (e) {
      stopPolling(); localStorage.removeItem(DISCOVER_JOB_KEY); setDiscovering(false);
      if (!isReattach) setError((e as Error).message);
    }
  }

  function startPolling(jobId: string, isReattach: boolean) {
    stopPolling();
    tick(jobId, isReattach);
    pollRef.current = setInterval(() => tick(jobId, isReattach), POLL_MS);
  }

  async function runDiscovery() {
    setError(null); setDiscovering(true);
    setDiscoverProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "starting" });
    try {
      const { job_id } = await api.iamDiscover({ ...authPayload(), idp_arn: selectedIdp });
      localStorage.setItem(DISCOVER_JOB_KEY, job_id);
      startPolling(job_id, false);
    } catch (e) {
      setError((e as Error).message); setDiscovering(false);
    }
  }

  // ─── Step 3: Migrate ────────────────────────────────────────────────────────
  async function runMigration() {
    setError(null); setMigrating(true); setMigrateResults([]);
    try {
      const res = await api.iamMigrate({
        ...authPayload(),
        role_arns: selectedRoles.map((r) => r.role_arn),
        mode: migrateMode,
        idp_arn: selectedIdp,
      });
      setMigrateResults(res.results as MigrateResult[]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setMigrating(false);
    }
  }

  // ─── Step 4: Generate IaC ──────────────────────────────────────────────────
  async function generateIac() {
    setError(null); setIacLoading(true);
    try {
      const res = await api.iamGenerateIac({
        role_arns: selectedRoles.length ? selectedRoles.map((r) => r.role_arn) : undefined,
      });
      setIacResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setIacLoading(false);
    }
  }

  // ─── CSV export ─────────────────────────────────────────────────────────────
  function handleExportRoles() {
    if (!roles.length) return;
    const rows = roles.flatMap((r) =>
      r.policies.length
        ? r.policies.map((p) => ({
            role_name: r.role_name,
            role_arn: r.role_arn,
            account_id: r.account_id,
            policy_name: p.policy_name,
            policy_type: p.policy_type,
            trust_summary: r.trust_summary,
          }))
        : [{
            role_name: r.role_name,
            role_arn: r.role_arn,
            account_id: r.account_id,
            policy_name: "(none)",
            policy_type: "N/A",
            trust_summary: r.trust_summary,
          }]
    );
    exportToCsv("iam_federation_roles.csv", rows, [
      { key: "role_name", header: "Role Name" },
      { key: "role_arn", header: "Role ARN" },
      { key: "account_id", header: "Account" },
      { key: "policy_name", header: "Policy Name" },
      { key: "policy_type", header: "Policy Type" },
      { key: "trust_summary", header: "Trust Policy" },
    ]);
  }

  function handleExportResults() {
    if (!migrateResults.length) return;
    exportToCsv("iam_federation_migration_results.csv", migrateResults.map((r) => ({
      role_name: r.role_name,
      role_arn: r.role_arn,
      status: r.status,
      mode: r.mode ?? "",
      error: r.error ?? r.reason ?? "",
    })), [
      { key: "role_name", header: "Role Name" },
      { key: "role_arn", header: "Role ARN" },
      { key: "status", header: "Status" },
      { key: "mode", header: "Mode" },
      { key: "error", header: "Error / Reason" },
    ]);
  }

  const discoverPct = discoverProgress && discoverProgress.total_units > 0
    ? Math.round((discoverProgress.completed_units / discoverProgress.total_units) * 100)
    : 0;

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Migrate SAML-federated IAM roles to AAM. This tool discovers roles that trust your SAML identity provider, then updates their trust policies to add the AAM service principal — enabling AAM to assume those roles on behalf of your users. Choose ADD mode to keep the existing SAML trust alongside AAM, or REPLACE mode to remove the SAML trust entirely.">
          IAM Federation → AAM
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && <Alert type="error" header="Error" dismissible onDismiss={() => setError(null)}>{error}</Alert>}

        {/* Credentials */}
        <Container header={<Header variant="h2">Credentials</Header>}>
          <AuthMethodSelect state={auth} onChange={setAuth} disabled={discovering || migrating} profileMode="multi" />
        </Container>

        {/* Step 1 — discover SAML providers */}
        <Container
          header={
            <Header variant="h2" description="Step 1 — discover SAML identity providers and select which one to evaluate.">
              Identity Providers
            </Header>
          }
        >
          <SpaceBetween size="m">
            <Button variant="primary" loading={loadingProviders} onClick={loadProviders} disabled={discovering}>
              List providers
            </Button>
            {providers.length > 0 && (
              <RadioGroup
                value={selectedIdp}
                onChange={({ detail }) => setSelectedIdp(detail.value)}
                items={providers.map((p) => ({
                  value: p.arn,
                  label: `${p.name}${p.is_identity_center ? " [Identity Center — auto-created]" : ""}`,
                  description: `${p.account_id} — ${p.arn}`,
                }))}
              />
            )}
          </SpaceBetween>
        </Container>

        {/* Step 2 — discover federated roles */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 2 — discover IAM roles with SAML trust policies referencing the selected provider."
              counter={roles.length ? `(${roles.length})` : undefined}
              actions={
                <Button iconName="download" onClick={handleExportRoles} disabled={!roles.length}>Export CSV</Button>
              }
            >
              Federated Roles
            </Header>
          }
        >
          <SpaceBetween size="m">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="primary" loading={discovering} disabled={!selectedIdp} onClick={runDiscovery}>
                Discover roles
              </Button>
              {cachedAt && (
                <StatusIndicator type="info">
                  Last discovery {formatAge(cachedAt)} ({formatAbsolute(cachedAt)})
                </StatusIndicator>
              )}
            </SpaceBetween>

            {discovering && discoverProgress && (
              <ProgressBar
                value={discoverPct}
                additionalInfo={(() => {
                  const parts: string[] = [];
                  if ((discoverProgress as any).activity) parts.push((discoverProgress as any).activity);
                  const scanned = (discoverProgress as any).roles_scanned;
                  const total = (discoverProgress as any).roles_total;
                  if (typeof scanned === "number" && scanned > 0) {
                    parts.push(`${scanned.toLocaleString()}${total ? ` / ${total.toLocaleString()}` : ""} roles scanned`);
                  }
                  return parts.length ? parts.join(" · ") : undefined;
                })()}
                description={discoverProgress.total_units > 0
                  ? `${discoverProgress.completed_units} / ${discoverProgress.total_units} account(s)`
                  : discoverProgress.message}
                label="Discovering"
              />
            )}

            <Table
              variant="embedded"
              resizableColumns
              selectionType="multi"
              selectedItems={selectedRoles}
              onSelectionChange={({ detail }) => setSelectedRoles(detail.selectedItems)}
              items={roles}
              trackBy="role_arn"
              empty={<Box textAlign="center">Discover roles to populate this table.</Box>}
              columnDefinitions={[
                { id: "role", header: "Role Name", cell: (r) => r.role_name, minWidth: 150 },
                { id: "arn", header: "ARN", cell: (r) => r.role_arn, minWidth: 200 },
                { id: "account", header: "Account", cell: (r) => r.account_id, minWidth: 120 },
                { id: "policies", header: "Policies", cell: (r) => r.policies.map((p) => p.policy_name).join(", ") || "(none)", minWidth: 200 },
                { id: "trust", header: "Trust Policy", cell: (r) => r.trust_summary, minWidth: 180 },
              ]}
            />
          </SpaceBetween>
        </Container>

        {/* Step 3 — Entitlement mapping */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 3 — define how your IdP group names map to AAM entitlements. Provide group names (paste or upload a file) and establish the naming pattern. The parsed {role} value is matched to the federated roles discovered in Step 2."
              counter={entitlementMappings.length ? `(${entitlementMappings.length} parsed)` : undefined}
            >
              Entitlement Mapping
            </Header>
          }
        >
          <SpaceBetween size="m">
            <FormField
              label="Group name pattern"
              description="Define the format of your IdP group names using placeholders: {principal}, {account}, {role}. The {role} component will be matched to the IAM role names discovered in Step 2."
              constraintText="Example: if your groups are named 'admins_123456789012_PowerUser', the pattern is '{principal}_{account}_{role}'"
            >
              <Input
                value={groupPattern}
                onChange={({ detail }) => setGroupPattern(detail.value)}
                placeholder="{principal}_{account}_{role}"
              />
            </FormField>

            <FormField
              label="Group names"
              description="Paste your IdP group names (one per line or comma-separated), or upload a text/CSV file."
            >
              <SpaceBetween size="xs">
                <Textarea
                  value={groupNamesRaw}
                  onChange={({ detail }) => setGroupNamesRaw(detail.value)}
                  placeholder={"admins_111111111111_PowerUser\ndevs_222222222222_ReadOnly\nengineers_111111111111_Admin"}
                  rows={6}
                />
                <Button iconName="upload" onClick={() => {
                  const input = document.createElement("input");
                  input.type = "file";
                  input.accept = ".csv,.txt";
                  input.onchange = (e) => {
                    const file = (e.target as HTMLInputElement).files?.[0];
                    if (!file) return;
                    const reader = new FileReader();
                    reader.onload = (ev) => {
                      const text = ev.target?.result as string;
                      setGroupNamesRaw(text);
                    };
                    reader.readAsText(file);
                  };
                  input.click();
                }}>Upload file</Button>
              </SpaceBetween>
            </FormField>

            <Button variant="primary" onClick={() => {
              // Parse group names using the pattern
              const groups = groupNamesRaw.split(/[\n,]+/).map((g) => g.trim()).filter(Boolean);
              // Build a regex from the pattern — detect separator from pattern
              const escaped = groupPattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
              const regexStr = escaped
                .replace("\\{principal\\}", "(?<principal>.+?)")
                .replace("\\{account\\}", "(?<account>\\d+)")
                .replace("\\{role\\}", "(?<role>.+)");
              const regex = new RegExp(`^${regexStr}$`);
              const parsed = groups.map((g) => {
                const match = g.match(regex);
                if (match?.groups) {
                  const roleParsed = match.groups.role || "";
                  // Match to discovered federated roles from Step 2
                  const matchedRole = roles.find((r) => r.role_name === roleParsed || r.role_name.toLowerCase() === roleParsed.toLowerCase());
                  return {
                    group: g,
                    principal: match.groups.principal || "",
                    account: match.groups.account || "",
                    role: roleParsed,
                    matchedRoleArn: matchedRole?.role_arn || "",
                    matchedRoleName: matchedRole?.role_name || "(no match in Step 2)",
                  };
                }
                return { group: g, principal: "(parse error)", account: "(parse error)", role: "(parse error)", matchedRoleArn: "", matchedRoleName: "(parse error)" };
              });
              setEntitlementMappings(parsed);
            }}>
              Parse group names
            </Button>

            {entitlementMappings.length > 0 && (
              <SpaceBetween size="s">
                {entitlementMappings.some((m) => m.matchedRoleName === "(no match in Step 2)") && (
                  <Alert type="warning">
                    Some parsed role names could not be matched to discovered federated roles from Step 2. Ensure the {"{role}"} component in your pattern matches the IAM role name exactly.
                  </Alert>
                )}
                <Table
                  variant="embedded"
                  resizableColumns
                  items={entitlementMappings}
                  trackBy="group"
                  columnDefinitions={[
                    { id: "group", header: "Group Name", cell: (m) => m.group, minWidth: 200 },
                    { id: "principal", header: "Principal", cell: (m) => m.principal, minWidth: 120 },
                    { id: "account", header: "Account", cell: (m) => m.account, minWidth: 120 },
                    { id: "role", header: "Parsed Role", cell: (m) => m.role, minWidth: 130 },
                    { id: "matched", header: "Matched IAM Role", cell: (m) => (
                      <StatusIndicator type={m.matchedRoleArn ? "success" : "warning"}>
                        {m.matchedRoleName}
                      </StatusIndicator>
                    ), minWidth: 180 },
                  ]}
                />
              </SpaceBetween>
            )}
          </SpaceBetween>
        </Container>

        {/* Step 4 — migrate trust policies */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 4 — update trust policies on selected roles to add the AAM service principal."
              actions={
                <Button iconName="download" onClick={handleExportResults} disabled={!migrateResults.length}>Export CSV</Button>
              }
            >
              Migrate
            </Header>
          }
        >
          <SpaceBetween size="m">
            <RadioGroup
              value={migrateMode}
              onChange={({ detail }) => setMigrateMode(detail.value as MigrateMode)}
              items={[
                { value: "ADD", label: "ADD", description: "Keep existing SAML trust statement, append the new AAM statement." },
                { value: "REPLACE", label: "REPLACE", description: "Remove the SAML trust statement, replace with the new AAM statement." },
              ]}
            />
            <Button variant="primary" loading={migrating} disabled={!selectedRoles.length} onClick={runMigration}>
              Migrate selected roles ({selectedRoles.length})
            </Button>

            {migrateResults.length > 0 && (
              <Table
                variant="embedded"
                resizableColumns
                items={migrateResults}
                trackBy="role_arn"
                columnDefinitions={[
                  { id: "role", header: "Role", cell: (r) => r.role_name, minWidth: 150 },
                  { id: "arn", header: "ARN", cell: (r) => r.role_arn, minWidth: 200 },
                  {
                    id: "status", header: "Status", minWidth: 100,
                    cell: (r) => (
                      <StatusIndicator type={r.status === "success" ? "success" : r.status === "skipped" ? "info" : "error"}>
                        {r.status}
                      </StatusIndicator>
                    ),
                  },
                  { id: "detail", header: "Detail", cell: (r) => r.error || r.reason || r.mode || "", minWidth: 150 },
                ]}
              />
            )}
          </SpaceBetween>
        </Container>

        {/* Step 5 — generate IaC templates */}
        <Container
          header={
            <Header variant="h2" description="Step 5 — generate CloudFormation and Terraform templates from the discovered roles.">
              Generate IaC
            </Header>
          }
        >
          <SpaceBetween size="m">
            <Button variant="primary" loading={iacLoading} disabled={!roles.length} onClick={generateIac}>
              Generate templates
            </Button>
            {iacResult && (
              <SpaceBetween direction="horizontal" size="xs">
                <Button onClick={() => setIacModal("cloudformation")}>View CloudFormation</Button>
                <Button onClick={() => setIacModal("terraform")}>View Terraform</Button>
                <StatusIndicator type="success">{iacResult.cloudformation.path}</StatusIndicator>
              </SpaceBetween>
            )}
          </SpaceBetween>
        </Container>
      </SpaceBetween>

      {/* IaC template modal */}
      <Modal
        visible={!!iacModal}
        size="max"
        onDismiss={() => setIacModal(null)}
        header={iacModal === "cloudformation" ? "CloudFormation Template" : "Terraform Configuration"}
        footer={<Box float="right"><Button variant="primary" onClick={() => setIacModal(null)}>Close</Button></Box>}
      >
        {iacResult && iacModal && (
          <Box variant="code">
            <pre style={{ margin: 0, maxHeight: "70vh", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {iacModal === "cloudformation" ? iacResult.cloudformation.content : iacResult.terraform.content}
            </pre>
          </Box>
        )}
      </Modal>
    </ContentLayout>
  );
}
