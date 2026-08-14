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
import Multiselect from "@cloudscape-design/components/multiselect";
import ProgressBar from "@cloudscape-design/components/progress-bar";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import Table from "@cloudscape-design/components/table";
import TextFilter from "@cloudscape-design/components/text-filter";
import Toggle from "@cloudscape-design/components/toggle";
import Pagination from "@cloudscape-design/components/pagination";
import { api, type CacheWrapper, type JobProgress } from "../api/client";
import { AuthMethodSelect, INITIAL_AUTH_STATE, parseAccountIds, type AuthState } from "../components/AuthMethodSelect";
import { type MultiOption } from "../components/ProfileSelect";
import { exportToCsv } from "../utils/csv";
import { formatAbsolute, formatAge } from "../utils/time";
import { useTablePagination } from "../utils/useTablePagination";
import { useNotifications } from "../utils/notifications";

interface Match {
  resource_arn: string;
  service: string;
  matched_terms: string[];
  account_id?: string;
  profile?: string;
  policy?: unknown;
}

interface ScanData {
  search_terms: string[];
  total_matches: number;
  regions_scanned: string[];
  matches: Match[];
  per_profile?: { profile: string; account_id?: string; matches?: number; status: string; error?: string; errors?: string[] }[];
  resume?: { total_units: number; skipped_units: number; resumed: boolean; complete: boolean };
}

const POLL_MS = 1000;
const JOB_KEY = "truffle.policyScanJob";

export default function PolicyAnalysis() {
  const { addNotification } = useNotifications();
  const [search, setSearch] = useState("");
  const [auth, setAuth] = useState<AuthState>(INITIAL_AUTH_STATE);
  const [services, setServices] = useState<MultiOption[]>([]);
  const [serviceOptions, setServiceOptions] = useState<MultiOption[]>([]);
  const [regions, setRegions] = useState("");
  const [mgmt, setMgmt] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<JobProgress | null>(null);
  const [, _setError] = useState<string | null>(null);
  const setError = (msg: string | null) => {
    _setError(msg);
    if (msg) addNotification("error", msg, "Policy Analysis Error");
  };
  const [result, setResult] = useState<ScanData | null>(null);
  const [cachedAt, setCachedAt] = useState<string | undefined>();
  const [policyMatch, setPolicyMatch] = useState<Match | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    api.policyServices().then((r) =>
      setServiceOptions(r.services.map((s) => ({ label: s, value: s })))
    );
    api.policyResult().then((r: CacheWrapper) => {
      if (r?.data) {
        setResult(r.data as ScanData);
        setCachedAt(r.cached_at);
      }
    });
    const saved = localStorage.getItem(JOB_KEY);
    if (saved) {
      setRunning(true);
      setProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "reconnecting…" });
      startPolling(saved, true);
    }
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function stopPolling() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }

  async function tick(jobId: string, isReattach: boolean) {
    try {
      const job = await api.policyStatus(jobId);
      setProgress(job.progress);
      if (job.status === "done" && job.result?.data) {
        stopPolling(); localStorage.removeItem(JOB_KEY);
        setResult(job.result.data as ScanData); setCachedAt(job.result.cached_at); setRunning(false);
      } else if (job.status === "error") {
        stopPolling(); localStorage.removeItem(JOB_KEY);
        setError(job.error || "Scan failed"); setRunning(false);
      }
    } catch (e) {
      stopPolling(); localStorage.removeItem(JOB_KEY); setRunning(false);
      if (!isReattach) setError((e as Error).message);
    }
  }

  function startPolling(jobId: string, isReattach: boolean) {
    stopPolling();
    tick(jobId, isReattach);
    pollRef.current = setInterval(() => tick(jobId, isReattach), POLL_MS);
  }

  const canRun =
    !!search &&
    (auth.operatingMode === "single"
      ? true
      : auth.authMethod === "profiles"
        ? true
        : parseAccountIds(auth.accountIds).length > 0 && !!auth.roleName.trim());

  async function runScan() {
    setError(null); setRunning(true);
    setProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "starting" });
    try {
      const common = {
        search_terms: search,
        services: services.map((s) => s.value),
        regions: regions ? regions.split(",").map((x) => x.trim()).filter(Boolean) : [],
        management_account: mgmt,
      };
      let payload: Record<string, unknown>;
      if (auth.operatingMode === "single") {
        // Single-account mode: use the default credential chain, no profiles or account IDs.
        payload = { ...common, auth_method: "profiles" };
      } else if (auth.authMethod === "assume_role") {
        payload = { ...common, auth_method: "assume_role", account_ids: parseAccountIds(auth.accountIds), role_name: auth.roleName.trim() };
      } else {
        payload = { ...common, auth_method: "profiles", profiles: auth.profiles.map((p) => p.value) };
      }
      const { job_id } = await api.policyScan(payload);
      localStorage.setItem(JOB_KEY, job_id);
      startPolling(job_id, false);
    } catch (e) { setError((e as Error).message); setRunning(false); }
  }

  const pct = progress && progress.total_units > 0 ? Math.round((progress.completed_units / progress.total_units) * 100) : 0;

  const liveActivity = (() => {
    if (!progress) return undefined;
    const parts: string[] = [];
    if (progress.activity) parts.push(progress.activity);
    if (typeof progress.resources === "number" && progress.resources > 0)
      parts.push(`${progress.resources.toLocaleString()} resources`);
    return parts.length ? parts.join(" · ") : progress.message;
  })();

  function formatPolicy(p: unknown): string {
    if (p == null) return "(no policy captured)";
    if (typeof p === "string") { try { return JSON.stringify(JSON.parse(p), null, 2); } catch { return p; } }
    return JSON.stringify(p, null, 2);
  }

  const matchesPagination = useTablePagination({
    items: result?.matches || [],
    pageSize: 25,
    filterFn: (m, q) => m.resource_arn.toLowerCase().includes(q) || m.service.toLowerCase().includes(q) || (m.account_id || "").includes(q) || m.matched_terms.some((t) => t.toLowerCase().includes(q)),
  });

  function handleExport() {
    if (!result?.matches.length) return;
    exportToCsv("policy_analysis_matches.csv", result.matches.map((m) => ({
      service: m.service,
      resource_arn: m.resource_arn,
      matched_terms: m.matched_terms.join("; "),
      account_id: m.account_id ?? "",
    })), [
      { key: "service", header: "Service" },
      { key: "resource_arn", header: "Resource ARN" },
      { key: "matched_terms", header: "Matched Terms" },
      { key: "account_id", header: "Account" },
    ]);
  }

  return (
    <ContentLayout
      header={
        <Header variant="h1" description="Scan resource-based policies (S3, KMS, SQS, SNS, Lambda, etc.), IAM trust policies, and Organization policies (SCPs/RCPs) across one or more accounts for specific strings — such as a principal ARN, account ID, or service name. Use this to identify policies that reference your Identity Center reserved roles before migrating to AAM.">
          Policy Analysis
        </Header>
      }
    >
      <SpaceBetween size="l">

        <Container header={<Header variant="h2">Credentials</Header>}>
          <AuthMethodSelect state={auth} onChange={setAuth} disabled={running} profileMode="multi" allowOrg={false} />
        </Container>

        <Container header={<Header variant="h2">Scan scope</Header>}>
          <SpaceBetween size="l">
            <FormField
              label="Search strings"
              description="Comma-separated terms to search for in policies. Matching is case-insensitive. Supports IAM-style wildcards: * (any characters) and ? (single character). Note: if your search term contains *, it will also match policies with concrete values in that position (e.g., searching arn:aws:iam::*:role/MyRole will match both wildcard references and specific account IDs)."
            >
              <Input value={search} onChange={({ detail }) => setSearch(detail.value)} placeholder="arn:aws:iam::*:role/MyRole*, my-saml-provider" disabled={running} />
            </FormField>

            <FormField label="Services" description="Optional. Limit the scan to specific resource types. Empty = all services.">
              <Multiselect selectedOptions={services} onChange={({ detail }) => setServices([...detail.selectedOptions])} options={serviceOptions} placeholder="All services" filteringType="auto" />
            </FormField>

            <FormField label="Regions" description="Optional comma-separated regions. Empty = all enabled regions.">
              <Input value={regions} onChange={({ detail }) => setRegions(detail.value)} placeholder="us-east-1, us-west-2" disabled={running} />
            </FormField>

            <Toggle checked={mgmt} onChange={({ detail }) => setMgmt(detail.checked)} disabled={running}>
              Also scan Organization SCPs and RCPs (management / delegated-admin account)
            </Toggle>

            <Button variant="primary" loading={running} disabled={!canRun} onClick={runScan}>Run scan</Button>

            {running && progress && (
              <ProgressBar
                value={pct}
                additionalInfo={liveActivity}
                description={progress.total_units > 0
                  ? `${progress.completed_units} / ${progress.total_units} units` + (progress.skipped_units > 0 ? ` · ${progress.skipped_units} resumed` : "")
                  : progress.message}
                label="Scanning"
              />
            )}
          </SpaceBetween>
        </Container>

        {result && (
          <Container
            header={
              <Header
                variant="h2"
                counter={`(${result.total_matches})`}
                description={cachedAt ? `Last run ${formatAge(cachedAt)} (${formatAbsolute(cachedAt)})` : undefined}
                actions={
                  <Button iconName="download" onClick={handleExport} disabled={!result.matches.length}>
                    Export CSV
                  </Button>
                }
              >
                Matches
              </Header>
            }
          >
            <SpaceBetween size="m">
              {result.resume?.resumed && (
                <StatusIndicator type="info">
                  Resumed: {result.resume.skipped_units} of {result.resume.total_units} units were reused from a previous run.
                </StatusIndicator>
              )}
              {result.per_profile?.some((p) => p.status === "error" || p.status === "partial") && (
                <Alert type="warning" header="Some accounts had errors">
                  {result.per_profile
                    .filter((p) => p.status === "error" || p.status === "partial")
                    .map((p) => `${p.profile}: ${p.error || (p.errors || []).join("; ")}`)
                    .join(" | ")}
                </Alert>
              )}
              <Table
                variant="embedded"
                resizableColumns
                items={matchesPagination.pageItems}
                filter={<TextFilter filteringPlaceholder="Filter by ARN, service, account, or matched term" filteringText={matchesPagination.filterQuery} onChange={({ detail }) => matchesPagination.setFilterQuery(detail.filteringText)} />}
                pagination={<Pagination currentPageIndex={matchesPagination.paginationProps.currentPageIndex} pagesCount={matchesPagination.paginationProps.pagesCount} onChange={matchesPagination.paginationProps.onChange} />}
                empty={<Box textAlign="center">No matching policies found.</Box>}
                columnDefinitions={[
                  { id: "service", header: "Service", cell: (m) => m.service, minWidth: 120 },
                  { id: "arn", header: "Resource ARN", cell: (m) => m.resource_arn, minWidth: 200 },
                  { id: "terms", header: "Matched terms", cell: (m) => m.matched_terms.join(", "), minWidth: 150 },
                  { id: "account", header: "Account", cell: (m) => m.account_id ?? "—", minWidth: 120 },
                  { id: "view", header: "Policy", cell: (m) => (<Button variant="inline-link" onClick={() => setPolicyMatch(m)}>View policy</Button>), minWidth: 110 },
                ]}
              />
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>

      <Modal visible={!!policyMatch} size="large" onDismiss={() => setPolicyMatch(null)} header={policyMatch ? `${policyMatch.service} — policy` : "Policy"}
        footer={<Box float="right"><Button variant="primary" onClick={() => setPolicyMatch(null)}>Close</Button></Box>}
      >
        {policyMatch && (
          <SpaceBetween size="s">
            <Box variant="small">{policyMatch.resource_arn}</Box>
            <Box variant="code">
              <pre style={{ margin: 0, maxHeight: "60vh", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                {formatPolicy(policyMatch.policy)}
              </pre>
            </Box>
          </SpaceBetween>
        )}
      </Modal>
    </ContentLayout>
  );
}
