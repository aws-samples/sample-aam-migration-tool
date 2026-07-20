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
import Pagination from "@cloudscape-design/components/pagination";
import ProgressBar from "@cloudscape-design/components/progress-bar";
import RadioGroup from "@cloudscape-design/components/radio-group";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Table from "@cloudscape-design/components/table";
import Textarea from "@cloudscape-design/components/textarea";
import TextFilter from "@cloudscape-design/components/text-filter";
import { api, type CacheWrapper, type JobProgress } from "../api/client";
import { INITIAL_AUTH_STATE, parseAccountIds, type AuthState } from "../components/AuthMethodSelect";
import { ProfileMultiSelect } from "../components/ProfileSelect";
import { exportToCsv } from "../utils/csv";
import { formatAbsolute, formatAge } from "../utils/time";
import { useTablePagination } from "../utils/useTablePagination";

interface PermissionSet {
  arn: string;
  name: string;
  description: string;
  session_duration: string;
  inline_policy: unknown | null;
  aws_managed_policies: { name: string; arn: string }[];
  customer_managed_policy_references: { name: string; path: string }[];
}

interface Assignment {
  permission_set_arn: string;
  permission_set_name: string;
  account_id: string;
  principal_type: string;
  principal_id: string;
  principal_display_name: string;
}

interface InventoryData {
  instance_arn: string;
  hub_account_id: string;
  account_scope: string;
  permission_sets: PermissionSet[];
  assignments: Assignment[];
  total_permission_sets: number;
  total_assignments: number;
}

const POLL_MS = 1000;
const DISCOVER_JOB_KEY = "truffle.idcDiscoverJob";

export default function Idc() {
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);
  const [error, setError] = useState<string | null>(null);
  const [region, setRegion] = useState("us-east-1");
  const [accountScope, setAccountScope] = useState<"single" | "multi" | "org">("single");
  const [targetAccountIds, setTargetAccountIds] = useState("");

  // Discovery
  const [discovering, setDiscovering] = useState(false);
  const [discoverProgress, setDiscoverProgress] = useState<JobProgress | null>(null);
  const [inventory, setInventory] = useState<InventoryData | null>(null);
  const [cachedAt, setCachedAt] = useState<string | undefined>();
  const [selectedPS, setSelectedPS] = useState<PermissionSet[]>([]);
  const [selectedAssignments, setSelectedAssignments] = useState<Assignment[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // IaC generation
  const [creationMode, setCreationMode] = useState<"generate-iac" | "apply">("generate-iac");
  const [iacLoading, setIacLoading] = useState(false);
  const [iacResult, setIacResult] = useState<{ templates: Record<string, { content: string; path: string }>; accounts: string[]; roles_count: number; entitlements_count: number } | null>(null);
  const [iacModalAccount, setIacModalAccount] = useState<string | null>(null);
  const [aamAppArn, setAamAppArn] = useState("");

  // Apply mode
  const [applying, setApplying] = useState(false);
  const [applyProgress, setApplyProgress] = useState<JobProgress | null>(null);
  const [applyResults, setApplyResults] = useState<{ role_name: string; role_arn: string; account_id: string; permission_set: string; status: string; error?: string; entitlement_status?: string }[]>([]);
  const applyPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [applyCreds, setApplyCreds] = useState<"same" | "different">("same");
  const [entitlementResults, setEntitlementResults] = useState<{ principal: string; principal_type: string; account_id: string; role_arn: string; status: string; error?: string }[]>([]);

  // Migration plan (editable role name mapping)
  const [roleMappings, setRoleMappings] = useState<{ key: string; psArn: string; psName: string; roleName: string; principal: string; accountId: string }[]>([]);
  const [rolePath, setRolePath] = useState("/aam/");

  // Load cached state on mount
  useEffect(() => {
    api.idcState().then((r: CacheWrapper) => {
      if (r?.data) {
        const inv = r.data as InventoryData;
        setInventory(inv);
        setCachedAt(r.cached_at);
        setRoleMappings(inv.assignments.map((a) => ({
          key: `${a.permission_set_arn}#${a.account_id}#${a.principal_id}`,
          psArn: a.permission_set_arn,
          psName: a.permission_set_name,
          roleName: `AAM-${a.permission_set_name}`,
          principal: a.principal_display_name,
          accountId: a.account_id,
        })));
      }
    });
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
  function discoverPayload(): Record<string, unknown> {
    const base: Record<string, unknown> = { region, account_scope: accountScope };
    if (accountScope === "single" || accountScope === "multi") {
      base.target_account_ids = parseAccountIds(targetAccountIds);
    }
    // Credentials are for IdC access only (the management/delegated-admin account)
    if (auth.authMethod === "assume_role") {
      return { ...base, auth_method: "assume_role", role_name: auth.roleName.trim(), account_ids: parseAccountIds(targetAccountIds) };
    }
    const profile = auth.singleProfile?.value || (auth.profiles.length ? auth.profiles[0].value : undefined);
    return { ...base, auth_method: "profiles", profile, profiles: auth.profiles.map((p) => p.value) };
  }

  function applyPayload(): Record<string, unknown> {
    const base = discoverPayload();
    const payload: Record<string, unknown> = { ...base, role_name_template: "AAM-{name}", role_path: rolePath };

    // For single-account with "different" credentials, override auth
    if (accountScope === "single" && applyCreds === "different") {
      if (auth.authMethod === "assume_role") {
        payload.auth_method = "assume_role";
        payload.role_name = auth.roleName.trim();
        payload.account_ids = parseAccountIds(targetAccountIds);
      } else {
        payload.auth_method = "profiles";
        payload.profiles = auth.profiles.map((p) => p.value);
      }
    }
    // For multi/org, the auth is already set in discoverPayload from the UI state
    return payload;
  }

  // Filter assignments based on selected permission sets
  const filteredAssignments = inventory
    ? selectedPS.length > 0
      ? inventory.assignments.filter((a) => selectedPS.some((ps) => ps.arn === a.permission_set_arn))
      : inventory.assignments
    : [];

  // Migration plan filtered by selected permission sets and assignments
  const filteredRoleMappings = (() => {
    if (!roleMappings.length) return [];
    let mappings = roleMappings;
    if (selectedPS.length > 0) {
      const selectedArns = new Set(selectedPS.map((ps) => ps.arn));
      mappings = mappings.filter((m) => selectedArns.has(m.psArn));
    }
    if (selectedAssignments.length > 0) {
      const selectedKeys = new Set(selectedAssignments.map((a) => `${a.permission_set_arn}#${a.account_id}#${a.principal_id}`));
      mappings = mappings.filter((m) => selectedKeys.has(m.key));
    }
    return mappings;
  })();

  // ─── Table pagination + filtering ───────────────────────────────────────────
  const psPagination = useTablePagination({
    items: inventory?.permission_sets || [],
    pageSize: 25,
    filterFn: (ps, q) => ps.name.toLowerCase().includes(q) || ps.description.toLowerCase().includes(q),
  });

  const assignPagination = useTablePagination({
    items: filteredAssignments,
    pageSize: 25,
    filterFn: (a, q) => a.principal_display_name.toLowerCase().includes(q) || a.account_id.includes(q) || a.permission_set_name.toLowerCase().includes(q),
  });

  const planPagination = useTablePagination({
    items: filteredRoleMappings,
    pageSize: 25,
    filterFn: (m, q) => m.psName.toLowerCase().includes(q) || m.roleName.toLowerCase().includes(q) || m.accountId.includes(q) || m.principal.toLowerCase().includes(q),
  });

  const canDiscover =
    accountScope === "org"
      ? true
      : parseAccountIds(targetAccountIds).length > 0;
    accountScope === "org"
      ? true
      : parseAccountIds(targetAccountIds).length > 0;

  // ─── Polling ────────────────────────────────────────────────────────────────
  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function tick(jobId: string, isReattach: boolean) {
    try {
      const job = await api.idcDiscoverStatus(jobId);
      setDiscoverProgress(job.progress);
      if (job.status === "done" && job.result?.data) {
        stopPolling(); localStorage.removeItem(DISCOVER_JOB_KEY);
        const inv = job.result.data as InventoryData;
        setInventory(inv);
        setCachedAt(job.result.cached_at);
        setDiscovering(false);
        // Auto-generate default role mappings from assignments
        setRoleMappings(inv.assignments.map((a) => ({
          key: `${a.permission_set_arn}#${a.account_id}#${a.principal_id}`,
          psArn: a.permission_set_arn,
          psName: a.permission_set_name,
          roleName: `AAM-${a.permission_set_name}`,
          principal: a.principal_display_name,
          accountId: a.account_id,
        })));
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
      const { job_id } = await api.idcDiscover(discoverPayload());
      localStorage.setItem(DISCOVER_JOB_KEY, job_id);
      startPolling(job_id, false);
    } catch (e) {
      setError((e as Error).message); setDiscovering(false);
    }
  }

  // ─── IaC generation ─────────────────────────────────────────────────────────
  async function generateIac() {
    setError(null); setIacLoading(true);
    try {
      const payload: Record<string, unknown> = {};
      if (selectedPS.length) {
        payload.selected_permission_sets = selectedPS.map((ps) => ps.arn);
      }
      if (selectedAssignments.length) {
        payload.selected_assignments = selectedAssignments.map((a) => ({
          permission_set_arn: a.permission_set_arn,
          account_id: a.account_id,
          principal_id: a.principal_id,
          principal_type: a.principal_type,
        }));
      }
      if (aamAppArn.trim()) {
        payload.aam_application_arn = aamAppArn.trim();
      }
      const res = await api.idcGenerateIac(payload);
      setIacResult(res);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setIacLoading(false);
    }
  }

  // ─── Apply mode ─────────────────────────────────────────────────────────────
  function stopApplyPolling() {
    if (applyPollRef.current) { clearInterval(applyPollRef.current); applyPollRef.current = null; }
  }

  async function applyTick(jobId: string) {
    try {
      const job = await api.idcApplyStatus(jobId);
      setApplyProgress(job.progress);
      if (job.status === "done" && job.result) {
        stopApplyPolling();
        const data = job.result as unknown as { results: typeof applyResults; entitlement_results?: { principal: string; principal_type: string; account_id: string; role_arn: string; status: string; error?: string }[] };
        // Merge entitlement status into role results for the role table
        const entMap = new Map<string, string>();
        for (const e of data.entitlement_results || []) {
          if (e.role_arn) entMap.set(e.role_arn, e.status);
        }
        const merged = (data.results || []).map((r) => ({
          ...r,
          entitlement_status: entMap.get(r.role_arn) || (r.status === "error" ? "skipped" : "not created"),
        }));
        setApplyResults(merged);
        setEntitlementResults(data.entitlement_results || []);
        setApplying(false);
      } else if (job.status === "error") {
        stopApplyPolling();
        setError(job.error || "Apply failed");
        setApplying(false);
      }
    } catch (e) {
      stopApplyPolling(); setApplying(false);
      setError((e as Error).message);
    }
  }

  async function runApply() {
    setError(null); setApplying(true); setApplyResults([]); setEntitlementResults([]);
    setApplyProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "starting" });
    try {
      const payload: Record<string, unknown> = {
        ...applyPayload(),
      };
      if (selectedPS.length) {
        payload.selected_permission_sets = selectedPS.map((ps) => ps.arn);
      }
      if (selectedAssignments.length) {
        payload.selected_assignments = selectedAssignments.map((a) => ({
          permission_set_arn: a.permission_set_arn,
          account_id: a.account_id,
          principal_id: a.principal_id,
          principal_type: a.principal_type,
        }));
      }
      if (aamAppArn.trim()) {
        payload.aam_application_arn = aamAppArn.trim();
      }
      const { job_id } = await api.idcApply(payload);
      stopApplyPolling();
      applyTick(job_id);
      applyPollRef.current = setInterval(() => applyTick(job_id), POLL_MS);
    } catch (e) {
      setError((e as Error).message); setApplying(false);
    }
  }

  // ─── CSV export ─────────────────────────────────────────────────────────────
  function handleExportPS() {
    if (!inventory?.permission_sets.length) return;
    exportToCsv("idc_permission_sets.csv", inventory.permission_sets.map((ps) => ({
      name: ps.name,
      arn: ps.arn,
      description: ps.description,
      session_duration: ps.session_duration,
      aws_managed_policies: ps.aws_managed_policies.map((p) => p.name).join("; "),
      customer_managed_policies: ps.customer_managed_policy_references.map((r) => r.name).join("; "),
      has_inline_policy: ps.inline_policy ? "Yes" : "No",
    })), [
      { key: "name", header: "Name" },
      { key: "arn", header: "ARN" },
      { key: "description", header: "Description" },
      { key: "session_duration", header: "Session Duration" },
      { key: "aws_managed_policies", header: "AWS Managed Policies" },
      { key: "customer_managed_policies", header: "Customer Managed Policies" },
      { key: "has_inline_policy", header: "Has Inline Policy" },
    ]);
  }

  function handleExportAssignments() {
    if (!filteredAssignments.length) return;
    exportToCsv("idc_assignments.csv", filteredAssignments.map((a) => ({ ...a })), [
      { key: "principal_display_name", header: "Principal" },
      { key: "principal_type", header: "Type" },
      { key: "permission_set_name", header: "Permission Set" },
      { key: "account_id", header: "Account" },
      { key: "principal_id", header: "Principal ID" },
    ]);
  }

  const discoverPct = discoverProgress && discoverProgress.total_units > 0
    ? Math.round((discoverProgress.completed_units / discoverProgress.total_units) * 100)
    : 0;

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Migrate from IAM Identity Center (IdC) to Account Access Manager (AAM). This tool inventories your IdC permission sets and account assignments, then recreates them as IAM roles with the AAM trust policy — either as CloudFormation templates for review and deployment, or directly via the AWS API. Entitlements that preserve who-can-access-what are generated alongside the roles.">
          IdC → AAM
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && <Alert type="error" header="Error" dismissible onDismiss={() => setError(null)}>{error}</Alert>}

        {/* Account Scope */}
        <Container
          header={
            <Header variant="h2" description="Select which accounts to pull permission sets and assignments for. Your credentials are used solely for IdC API access (management or delegated-admin account).">
              Account Scope
            </Header>
          }
        >
          <SpaceBetween size="m">
            <RadioGroup
              value={accountScope}
              onChange={({ detail }) => setAccountScope(detail.value as "single" | "multi" | "org")}
              items={[
                { value: "single", label: "Single account", description: "Pull permission sets and assignments for one specific account.", disabled: discovering },
                { value: "multi", label: "Multiple accounts", description: "Pull permission sets and assignments for specific accounts.", disabled: discovering },
                { value: "org", label: "Entire organization", description: "Pull all permission sets and assignments across all provisioned accounts. May take longer and is subject to API rate limits.", disabled: discovering },
              ]}
            />
            {(accountScope === "single" || accountScope === "multi") && (
              <FormField
                label={accountScope === "single" ? "Account ID" : "Account IDs"}
                description={accountScope === "single"
                  ? "The 12-digit account ID to pull permission sets and assignments for."
                  : "Comma- or newline-separated 12-digit account IDs to filter permission sets and assignments for."}
              >
                {accountScope === "single" ? (
                  <Input
                    value={targetAccountIds}
                    onChange={({ detail }) => setTargetAccountIds(detail.value)}
                    placeholder="123456789012"
                    disabled={discovering}
                  />
                ) : (
                  <Textarea
                    value={targetAccountIds}
                    onChange={({ detail }) => setTargetAccountIds(detail.value)}
                    placeholder={"111111111111\n222222222222"}
                    rows={3}
                    disabled={discovering}
                  />
                )}
              </FormField>
            )}
            {accountScope === "org" && (
              <Alert type="warning">
                Organization-wide scans query all accounts provisioned in your Identity Center instance. In large organizations this may be throttled and take significantly longer.
              </Alert>
            )}
            <FormField label="IdC region" description="The primary region of your Identity Center instance.">
              <Input value={region} onChange={({ detail }) => setRegion(detail.value)} placeholder="us-east-1" disabled={discovering} />
            </FormField>
          </SpaceBetween>
        </Container>

        {/* Step 1 — Run inventory */}
        <Container
          header={
            <Header
              variant="h2"
              description="Step 1 — discover permission sets and assignments from your IdC instance."
              counter={inventory ? `(${inventory.total_permission_sets} permission sets, ${inventory.total_assignments} assignments)` : undefined}
            >
              Discovery
            </Header>
          }
        >
          <SpaceBetween size="m">
            <SpaceBetween direction="horizontal" size="xs">
              <Button variant="primary" loading={discovering} disabled={!canDiscover} onClick={runDiscovery}>
                Run discovery
              </Button>
              {cachedAt && (
                <StatusIndicator type="info">
                  Last run {formatAge(cachedAt)} ({formatAbsolute(cachedAt)})
                </StatusIndicator>
              )}
            </SpaceBetween>

            {discovering && discoverProgress && (
              <ProgressBar
                value={discoverPct}
                additionalInfo={(discoverProgress as any).phase ? `Phase: ${(discoverProgress as any).phase}` : undefined}
                description={discoverProgress.total_units > 0
                  ? `${discoverProgress.completed_units} / ${discoverProgress.total_units}`
                  : discoverProgress.message}
                label="Discovering"
              />
            )}
          </SpaceBetween>
        </Container>

        {/* Step 2 — Permission sets */}
        {inventory && (
          <Container
            header={
              <Header
                variant="h2"
                description="Step 2 — select the permission sets to migrate. Only selected permission sets will be included in role creation. Leave empty to include all."
                counter={selectedPS.length ? `(${selectedPS.length} of ${inventory.permission_sets.length} selected)` : `(${inventory.permission_sets.length})`}
                actions={
                  <Button iconName="download" onClick={handleExportPS} disabled={!inventory.permission_sets.length}>Export CSV</Button>
                }
              >
                Permission Sets
              </Header>
            }
          >
            <SpaceBetween size="s">
              {selectedPS.length > 0 && (
                <Alert type="info">
                  <b>{selectedPS.length}</b> permission set(s) selected for migration. The assignments table below is filtered to show only assignments for the selected permission sets.
                </Alert>
              )}
              <Table
                variant="embedded"
                resizableColumns
                selectionType="multi"
                selectedItems={selectedPS}
                onSelectionChange={({ detail }) => { setSelectedPS(detail.selectedItems); setSelectedAssignments([]); }}
                items={psPagination.pageItems}
                trackBy="arn"
                filter={<TextFilter filteringPlaceholder="Filter permission sets" filteringText={psPagination.filterQuery} onChange={({ detail }) => psPagination.setFilterQuery(detail.filteringText)} />}
                pagination={<Pagination {...psPagination.paginationProps} />}
                empty={<Box textAlign="center">No permission sets found.</Box>}
                columnDefinitions={[
                  { id: "name", header: "Name", cell: (ps) => ps.name, minWidth: 150 },
                  { id: "description", header: "Description", cell: (ps) => ps.description || "—", minWidth: 200 },
                  { id: "managed", header: "AWS Managed Policies", cell: (ps) => ps.aws_managed_policies.map((p) => p.name).join(", ") || "—", minWidth: 200 },
                  { id: "cmp", header: "Customer Managed Policies", cell: (ps) => ps.customer_managed_policy_references.map((r) => r.name).join(", ") || "—", minWidth: 180 },
                  { id: "inline", header: "Inline", cell: (ps) => ps.inline_policy ? "Yes" : "No", minWidth: 70 },
                  { id: "duration", header: "Session Duration (ISO 8601)", cell: (ps) => ps.session_duration, minWidth: 80 },
                ]}
              />
            </SpaceBetween>
          </Container>
        )}

        {/* Step 2b — Assignments */}
        {inventory && inventory.assignments.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                description="Step 2b — select which assignments (entitlements) to create. Only selected assignments will be included in the migration. Leave empty to include all visible assignments."
                counter={selectedAssignments.length ? `(${selectedAssignments.length} of ${filteredAssignments.length} selected)` : `(${filteredAssignments.length})`}
                actions={
                  <Button iconName="download" onClick={handleExportAssignments} disabled={!filteredAssignments.length}>Export CSV</Button>
                }
              >
                Assignments
              </Header>
            }
          >
            <SpaceBetween size="s">
              {selectedPS.length > 0 && (
                <Alert type="info">
                  Showing assignments filtered to the {selectedPS.length} selected permission set(s).
                </Alert>
              )}
              <Table
                variant="embedded"
                resizableColumns
                selectionType="multi"
                selectedItems={selectedAssignments}
                onSelectionChange={({ detail }) => setSelectedAssignments(detail.selectedItems)}
                items={assignPagination.pageItems}
                trackBy={(a) => `${a.permission_set_arn}#${a.account_id}#${a.principal_id}`}
                filter={<TextFilter filteringPlaceholder="Filter by principal, account, or permission set" filteringText={assignPagination.filterQuery} onChange={({ detail }) => assignPagination.setFilterQuery(detail.filteringText)} />}
                pagination={<Pagination {...assignPagination.paginationProps} />}
                empty={<Box textAlign="center">No assignments found.</Box>}
                columnDefinitions={[
                  { id: "principal", header: "Principal", cell: (a) => a.principal_display_name, minWidth: 150 },
                  { id: "type", header: "Type", cell: (a) => a.principal_type, minWidth: 80 },
                  { id: "ps", header: "Permission Set", cell: (a) => a.permission_set_name, minWidth: 150 },
                  { id: "account", header: "Account", cell: (a) => a.account_id, minWidth: 120 },
                ]}
              />
            </SpaceBetween>
          </Container>
        )}

        {/* Step 3 — Migration plan (role name mapping) */}
        {inventory && filteredRoleMappings.length > 0 && (
          <Container
            header={
              <Header
                variant="h2"
                description="Step 3 — review and customize the role name mapping. Each permission set maps to an IAM role. Edit role names inline or download the mapping, edit externally, and re-upload (CSV format)."
                counter={selectedPS.length || selectedAssignments.length ? `(${filteredRoleMappings.length} of ${roleMappings.length} shown)` : `(${roleMappings.length} mappings)`}
                actions={
                  <SpaceBetween direction="horizontal" size="xs">
                    <Button iconName="download" onClick={() => {
                      exportToCsv("migration_plan.csv", roleMappings.map((m) => ({
                        permission_set_name: m.psName,
                        permission_set_arn: m.psArn,
                        role_name: m.roleName,
                        role_path: rolePath,
                        principal: m.principal,
                        account_id: m.accountId,
                        full_role_arn: `arn:aws:iam::${m.accountId || "<ACCOUNT>"}:role${rolePath}${m.roleName}`,
                      })), [
                        { key: "permission_set_name", header: "Permission Set" },
                        { key: "permission_set_arn", header: "Permission Set ARN" },
                        { key: "role_name", header: "Role Name" },
                        { key: "role_path", header: "Role Path" },
                        { key: "principal", header: "Principal" },
                        { key: "account_id", header: "Account ID" },
                        { key: "full_role_arn", header: "Full Role ARN (template)" },
                      ]);
                    }}>Download CSV</Button>
                    <Button iconName="upload" onClick={() => {
                      const input = document.createElement("input");
                      input.type = "file";
                      input.accept = ".csv";
                      input.onchange = (e) => {
                        const file = (e.target as HTMLInputElement).files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = (ev) => {
                          const text = ev.target?.result as string;
                          const lines = text.split("\n").filter((l) => l.trim());
                          if (lines.length < 2) return;
                          // Parse CSV: expect headers including "Permission Set ARN" and "Role Name"
                          const headers = lines[0].split(",").map((h) => h.trim().replace(/^"|"$/g, ""));
                          const arnIdx = headers.findIndex((h) => h.toLowerCase().includes("permission set arn") || h.toLowerCase() === "permission_set_arn");
                          const roleIdx = headers.findIndex((h) => h.toLowerCase().includes("role name") || h.toLowerCase() === "role_name");
                          const principalIdx = headers.findIndex((h) => h.toLowerCase() === "principal");
                          const accountIdx = headers.findIndex((h) => h.toLowerCase().includes("account") && h.toLowerCase() !== "full role arn (template)");
                          if (arnIdx === -1 || roleIdx === -1) { setError("CSV must have 'Permission Set ARN' and 'Role Name' columns."); return; }
                          const uploaded: typeof roleMappings = [];
                          for (let i = 1; i < lines.length; i++) {
                            const cols = lines[i].split(",").map((c) => c.trim().replace(/^"|"$/g, ""));
                            const arn = cols[arnIdx] || "";
                            const rn = cols[roleIdx] || "";
                            const principal = principalIdx >= 0 ? cols[principalIdx] || "" : "";
                            const acctId = accountIdx >= 0 ? cols[accountIdx] || "" : "";
                            if (!arn) continue;
                            const existing = roleMappings.find((m) => m.psArn === arn);
                            uploaded.push({ key: `${arn}#${acctId}#${principal}`, psArn: arn, psName: existing?.psName || arn.split("/").pop() || "", roleName: rn, principal: principal || existing?.principal || "", accountId: acctId || existing?.accountId || "" });
                          }
                          if (uploaded.length) setRoleMappings(uploaded);
                        };
                        reader.readAsText(file);
                      };
                      input.click();
                    }}>Upload CSV</Button>
                  </SpaceBetween>
                }
              >
                Migration Plan
              </Header>
            }
          >
            <SpaceBetween size="m">
              <FormField label="Role path" description="IAM path applied to all created roles. This determines where the roles live in the IAM namespace.">
                <Input value={rolePath} onChange={({ detail }) => setRolePath(detail.value)} placeholder="/aam/" />
              </FormField>
              <Alert type="info">
                Roles will be created at <b>{rolePath}</b>. Full ARN pattern: <code>arn:aws:iam::&lt;account&gt;:role{rolePath}&lt;RoleName&gt;</code>
              </Alert>
              <Table
                variant="embedded"
                resizableColumns
                items={planPagination.pageItems}
                trackBy="key"
                filter={<TextFilter filteringPlaceholder="Filter by permission set, role name, principal, or account" filteringText={planPagination.filterQuery} onChange={({ detail }) => planPagination.setFilterQuery(detail.filteringText)} />}
                pagination={<Pagination {...planPagination.paginationProps} />}
                columnDefinitions={[
                  { id: "ps", header: "Permission Set", cell: (r) => r.psName, minWidth: 150 },
                  { id: "role", header: "Target Role Name", cell: (r) => (
                    <Input
                      value={r.roleName}
                      onChange={({ detail }) => {
                        setRoleMappings((prev) => prev.map((m) => m.key === r.key ? { ...m, roleName: detail.value } : m));
                      }}
                    />
                  ), minWidth: 200 },
                  { id: "principal", header: "Principal", cell: (r) => (
                    <Input
                      value={r.principal}
                      onChange={({ detail }) => {
                        setRoleMappings((prev) => prev.map((m) => m.key === r.key ? { ...m, principal: detail.value } : m));
                      }}
                      placeholder="group or user name"
                    />
                  ), minWidth: 150 },
                  { id: "account", header: "Account ID", cell: (r) => (
                    <Input
                      value={r.accountId}
                      onChange={({ detail }) => {
                        setRoleMappings((prev) => prev.map((m) => m.key === r.key ? { ...m, accountId: detail.value } : m));
                      }}
                      placeholder="123456789012"
                    />
                  ), minWidth: 130 },
                  { id: "path", header: "Role Path", cell: () => rolePath, minWidth: 80 },
                ]}
              />
            </SpaceBetween>
          </Container>
        )}

        {/* Step 4 — Role & Entitlement Creation */}
        {inventory && (
          <Container
            header={
              <Header variant="h2" description="Step 4 — create IAM roles and AAM entitlements. The AAM application ARN is required so that entitlements can be properly created within Account Access Manager.">
                Role &amp; Entitlement Creation
              </Header>
            }
          >
            <SpaceBetween size="m">
              <RadioGroup
                value={creationMode}
                onChange={({ detail }) => setCreationMode(detail.value as "generate-iac" | "apply")}
                items={[
                  { value: "generate-iac", label: "Generate CloudFormation", description: "Produce per-account CloudFormation templates. No changes are made to your AWS environment." },
                  { value: "apply", label: "Apply directly", description: "Create IAM roles and attach policies live via the AWS API. This will modify your environment." },
                ]}
              />

              <FormField
                label="AAM Application ARN"
                description="Required. The ARN of your pre-existing AAM application. Entitlements are created against this application to preserve who-can-access-what."
                constraintText="This must be created before using this tool. The tool does not create AAM applications."
              >
                <Input
                  value={aamAppArn}
                  onChange={({ detail }) => setAamAppArn(detail.value)}
                  placeholder="arn:aws:account-access:us-east-1:123456789012:application/app-id"
                />
              </FormField>

              {creationMode === "generate-iac" ? (
                <>
                  <Button variant="primary" loading={iacLoading} disabled={!inventory.permission_sets.length || !aamAppArn.trim()} onClick={generateIac}>
                    Generate template {selectedPS.length ? `(${selectedPS.length} permission sets` : "(all"}{selectedAssignments.length ? `, ${selectedAssignments.length} assignments)` : ")"}
                  </Button>
                  {iacResult && (
                    <SpaceBetween size="s">
                      <StatusIndicator type="success">
                        {iacResult.roles_count} role(s), {iacResult.entitlements_count} entitlement(s) across {iacResult.accounts.length} account(s)
                      </StatusIndicator>
                      <SpaceBetween direction="horizontal" size="xs">
                        {iacResult.accounts.map((acct) => (
                          <Button key={acct} onClick={() => setIacModalAccount(acct)}>
                            {iacResult.accounts.length > 1 ? `Account ${acct}` : "View CloudFormation"}
                          </Button>
                        ))}
                      </SpaceBetween>
                    </SpaceBetween>
                  )}
                </>
              ) : (
                <>
                  <Alert type="warning">
                    <b>This will modify your AWS environment.</b> IAM roles will be created in the
                    target account(s) with the AAM trust policy and policies from each permission set.
                    Existing roles with the same name will be skipped (idempotent).
                  </Alert>
                  {accountScope !== "single" && (
                    <Container header={<Header variant="h3" description="Credentials for creating roles in target accounts. Since changes span multiple accounts, specify how to authenticate into each.">Target Account Credentials</Header>}>
                      <SpaceBetween size="m">
                        <RadioGroup
                          value={auth.authMethod}
                          onChange={({ detail }) => setAuth({ ...auth, authMethod: detail.value as "profiles" | "assume_role" })}
                          items={[
                            { value: "profiles", label: "AWS credential profiles", description: "Use a named profile for each target account. The profile's account is resolved automatically via GetCallerIdentity.", disabled: applying },
                            { value: "assume_role", label: "Assume a common role", description: "Assume a single role name in each target account using your default credentials.", disabled: applying },
                          ]}
                        />
                        {auth.authMethod === "profiles" ? (
                          <FormField label="AWS profiles" description="One or more profiles — each will be resolved to its account ID automatically.">
                            <ProfileMultiSelect selected={auth.profiles} onChange={(profiles) => setAuth({ ...auth, profiles })} />
                          </FormField>
                        ) : (
                          <FormField label="Role name" description="Name (not ARN) of the role to assume in each target account. Your default credentials must have sts:AssumeRole permission.">
                            <Input value={auth.roleName} onChange={({ detail }) => setAuth({ ...auth, roleName: detail.value })} placeholder="OrganizationAccountAccessRole" disabled={applying} />
                          </FormField>
                        )}
                      </SpaceBetween>
                    </Container>
                  )}
                  {accountScope === "single" && (
                    <Container header={<Header variant="h3" description="Credentials for creating roles in the target account.">Target Account Credentials</Header>}>
                      <SpaceBetween size="m">
                        <RadioGroup
                          value={applyCreds}
                          onChange={({ detail }) => setApplyCreds(detail.value as "same" | "different")}
                          items={[
                            { value: "same", label: "Use same credentials", description: "Use the same credentials used for IdC discovery (your default credential chain).", disabled: applying },
                            { value: "different", label: "Specify different credentials", description: "Use a different profile or role for creating roles in the target account.", disabled: applying },
                          ]}
                        />
                        {applyCreds === "different" && (
                          <RadioGroup
                            value={auth.authMethod}
                            onChange={({ detail }) => setAuth({ ...auth, authMethod: detail.value as "profiles" | "assume_role" })}
                            items={[
                              { value: "profiles", label: "AWS credential profile", disabled: applying },
                              { value: "assume_role", label: "Assume a role", disabled: applying },
                            ]}
                          />
                        )}
                        {applyCreds === "different" && auth.authMethod === "profiles" && (
                          <FormField label="AWS profile" description="Profile with permissions to create roles in the target account.">
                            <ProfileMultiSelect selected={auth.profiles} onChange={(profiles) => setAuth({ ...auth, profiles })} />
                          </FormField>
                        )}
                        {applyCreds === "different" && auth.authMethod === "assume_role" && (
                          <FormField label="Role name" description="Role to assume in the target account.">
                            <Input value={auth.roleName} onChange={({ detail }) => setAuth({ ...auth, roleName: detail.value })} placeholder="AdminRole" disabled={applying} />
                          </FormField>
                        )}
                      </SpaceBetween>
                    </Container>
                  )}
                  <Button variant="primary" loading={applying} disabled={!inventory.permission_sets.length || !aamAppArn.trim()} onClick={runApply}>
                    Apply {selectedPS.length ? `(${selectedPS.length} permission sets` : "(all"}{selectedAssignments.length ? `, ${selectedAssignments.length} assignments)` : ")"}
                  </Button>
                  {applying && applyProgress && (
                    <ProgressBar
                      value={applyProgress.total_units > 0 ? Math.round((applyProgress.completed_units / applyProgress.total_units) * 100) : 0}
                      description={applyProgress.total_units > 0
                        ? `${applyProgress.completed_units} / ${applyProgress.total_units} role(s)`
                        : applyProgress.message}
                      label="Applying"
                    />
                  )}
                  {applyResults.length > 0 && (
                    <SpaceBetween size="m">
                      <Header variant="h3">Role Creation Results</Header>
                      <Table
                        variant="embedded"
                        resizableColumns
                        items={applyResults}
                        trackBy="role_arn"
                        columnDefinitions={[
                          { id: "role", header: "Role", cell: (r) => r.role_name, minWidth: 150 },
                          { id: "account", header: "Account", cell: (r) => r.account_id, minWidth: 120 },
                          { id: "ps", header: "Permission Set", cell: (r) => r.permission_set, minWidth: 150 },
                          { id: "status", header: "Status", minWidth: 100, cell: (r) => (
                            <StatusIndicator type={r.status === "created" ? "success" : r.status === "already exists" ? "info" : "error"}>
                              {r.status}
                            </StatusIndicator>
                          )},
                          { id: "error", header: "Detail", cell: (r) => r.error || "No errors", minWidth: 150 },
                        ]}
                      />
                    </SpaceBetween>
                  )}
                  {entitlementResults.length > 0 && (
                    <SpaceBetween size="m">
                      <Header variant="h3">Entitlement Results</Header>
                      <Table
                        variant="embedded"
                        resizableColumns
                        items={entitlementResults}
                        trackBy={(e) => `${e.role_arn}#${e.principal}#${e.account_id}`}
                        columnDefinitions={[
                          { id: "principal", header: "Principal", cell: (e) => e.principal, minWidth: 150 },
                          { id: "type", header: "Type", cell: (e) => e.principal_type, minWidth: 80 },
                          { id: "account", header: "Account", cell: (e) => e.account_id, minWidth: 120 },
                          { id: "role", header: "Role ARN", cell: (e) => e.role_arn, minWidth: 200 },
                          { id: "status", header: "Status", minWidth: 110, cell: (e) => (
                            <StatusIndicator type={e.status === "created" ? "success" : e.status === "existing" ? "info" : e.status === "skipped" ? "stopped" : "error"}>
                              {e.status}
                            </StatusIndicator>
                          )},
                          { id: "error", header: "Detail", cell: (e) => e.error || "No errors", minWidth: 150 },
                        ]}
                      />
                    </SpaceBetween>
                  )}
                </>
              )}
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>

      {/* IaC template modal (per-account) */}
      <Modal
        visible={!!iacModalAccount}
        size="max"
        onDismiss={() => setIacModalAccount(null)}
        header={iacModalAccount ? `CloudFormation — Account ${iacModalAccount}` : "CloudFormation"}
        footer={<Box float="right"><Button variant="primary" onClick={() => setIacModalAccount(null)}>Close</Button></Box>}
      >
        {iacResult && iacModalAccount && iacResult.templates[iacModalAccount] && (
          <Box variant="code">
            <pre style={{ margin: 0, maxHeight: "70vh", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              {iacResult.templates[iacModalAccount].content}
            </pre>
          </Box>
        )}
      </Modal>
    </ContentLayout>
  );
}
