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
import Toggle from "@cloudscape-design/components/toggle";
import { api, type CacheWrapper, type JobProgress } from "../api/client";
import { ProfileMultiSelect, type MultiOption } from "../components/ProfileSelect";
import { formatAbsolute, formatAge } from "../utils/time";

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
// Persist the running job id so switching tabs (which unmounts this page) — or
// even a browser refresh — doesn't lose track of an in-flight scan. The job
// runs on the backend; we just re-attach and resume polling.
const JOB_KEY = "truffle.policyScanJob";

export default function PolicyAnalysis() {
  const [search, setSearch] = useState("");
  const [profiles, setProfiles] = useState<MultiOption[]>([]);
  const [services, setServices] = useState<MultiOption[]>([]);
  const [serviceOptions, setServiceOptions] = useState<MultiOption[]>([]);
  const [regions, setRegions] = useState("");
  const [mgmt, setMgmt] = useState(false);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<JobProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanData | null>(null);
  const [cachedAt, setCachedAt] = useState<string | undefined>();
  const [policyMatch, setPolicyMatch] = useState<Match | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load the service list and any prior cached result on mount.
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
    // Re-attach to an in-flight scan if one was running when we last left.
    const saved = localStorage.getItem(JOB_KEY);
    if (saved) {
      setRunning(true);
      setProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "reconnecting…" });
      startPolling(saved, true);
    }
    // Stop the local timer if the component unmounts (tab switch). The backend
    // job keeps running; we re-attach on the next mount.
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function stopPolling() {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }

  // One poll of a job's status. ``isReattach`` suppresses the error toast when
  // a re-attached job is simply gone (e.g. server restarted).
  async function tick(jobId: string, isReattach: boolean) {
    try {
      const job = await api.policyStatus(jobId);
      setProgress(job.progress);
      if (job.status === "done" && job.result?.data) {
        stopPolling();
        localStorage.removeItem(JOB_KEY);
        setResult(job.result.data as ScanData);
        setCachedAt(job.result.cached_at);
        setRunning(false);
      } else if (job.status === "error") {
        stopPolling();
        localStorage.removeItem(JOB_KEY);
        setError(job.error || "Scan failed");
        setRunning(false);
      }
    } catch (e) {
      // 404 after a server restart, etc. Re-running resumes from checkpoint.
      stopPolling();
      localStorage.removeItem(JOB_KEY);
      setRunning(false);
      if (!isReattach) setError((e as Error).message);
    }
  }

  function startPolling(jobId: string, isReattach: boolean) {
    stopPolling();
    tick(jobId, isReattach); // immediate poll so the bar fills without a 1s wait
    pollRef.current = setInterval(() => tick(jobId, isReattach), POLL_MS);
  }

  async function runScan() {
    setError(null);
    setRunning(true);
    setProgress({ completed_units: 0, total_units: 0, skipped_units: 0, message: "starting" });
    try {
      const { job_id } = await api.policyScan({
        search_terms: search,
        profiles: profiles.map((p) => p.value),
        services: services.map((s) => s.value),
        regions: regions ? regions.split(",").map((x) => x.trim()).filter(Boolean) : [],
        management_account: mgmt,
      });
      localStorage.setItem(JOB_KEY, job_id);
      startPolling(job_id, false);
    } catch (e) {
      setError((e as Error).message);
      setRunning(false);
    }
  }

  const pct =
    progress && progress.total_units > 0
      ? Math.round((progress.completed_units / progress.total_units) * 100)
      : 0;

  // One-line live activity: current service + resources scanned this run.
  // Updates every poll so progress is visibly moving between unit ticks.
  const liveActivity = (() => {
    if (!progress) return undefined;
    const parts: string[] = [];
    if (progress.activity) parts.push(progress.activity);
    if (typeof progress.resources === "number" && progress.resources > 0) {
      parts.push(`${progress.resources.toLocaleString()} resources`);
    }
    return parts.length ? parts.join(" · ") : progress.message;
  })();

  function formatPolicy(p: unknown): string {
    if (p == null) return "(no policy captured)";
    if (typeof p === "string") {
      try {
        return JSON.stringify(JSON.parse(p), null, 2);
      } catch {
        return p;
      }
    }
    return JSON.stringify(p, null, 2);
  }

  return (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description="Scan resource-based policies across accounts for one or more search strings. Uses your local AWS credential chain. Interrupted scans resume from a local checkpoint."
        >
          Policy Analysis
        </Header>
      }
    >
      <SpaceBetween size="l">
        {error && <Alert type="error" header="Scan failed" dismissible onDismiss={() => setError(null)}>{error}</Alert>}

        <Container header={<Header variant="h2">Scan scope</Header>}>
          <SpaceBetween size="l">
            <FormField
              label="Search strings"
              description="Comma-separated. e.g. a role ARN or principal to find in policies."
            >
              <Input
                value={search}
                onChange={({ detail }) => setSearch(detail.value)}
                placeholder="arn:aws:iam::1111:role/Example, my-search-term"
                disabled={running}
              />
            </FormField>

            <FormField
              label="AWS profiles"
              description="One or more profiles to scan. Each is scanned as its own account, in parallel. Leave empty to use the default credential chain."
            >
              <ProfileMultiSelect selected={profiles} onChange={setProfiles} />
            </FormField>

            <FormField
              label="Services"
              description="Optional. Limit the scan to specific resource types. Empty = all services."
            >
              <Multiselect
                selectedOptions={services}
                onChange={({ detail }) => setServices([...detail.selectedOptions])}
                options={serviceOptions}
                placeholder="All services"
                filteringType="auto"
              />
            </FormField>

            <FormField label="Regions" description="Optional comma-separated regions. Empty = all enabled regions.">
              <Input
                value={regions}
                onChange={({ detail }) => setRegions(detail.value)}
                placeholder="us-east-1, us-west-2"
                disabled={running}
              />
            </FormField>

            <Toggle checked={mgmt} onChange={({ detail }) => setMgmt(detail.checked)} disabled={running}>
              Also scan Organization SCPs and RCPs (management / delegated-admin account)
            </Toggle>

            <Button variant="primary" loading={running} disabled={!search} onClick={runScan}>
              Run scan
            </Button>

            {running && progress && (
              <ProgressBar
                value={pct}
                additionalInfo={liveActivity}
                description={
                  progress.total_units > 0
                    ? `${progress.completed_units} / ${progress.total_units} units` +
                      (progress.skipped_units > 0
                        ? ` · ${progress.skipped_units} resumed`
                        : "")
                    : progress.message
                }
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
              >
                Matches
              </Header>
            }
          >
            <SpaceBetween size="m">
              {result.resume?.resumed && (
                <StatusIndicator type="info">
                  Resumed: {result.resume.skipped_units} of {result.resume.total_units} units were
                  reused from a previous run.
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
                items={result.matches}
                empty={<Box textAlign="center">No matching policies found.</Box>}
                columnDefinitions={[
                  { id: "service", header: "Service", cell: (m) => m.service },
                  { id: "arn", header: "Resource ARN", cell: (m) => m.resource_arn },
                  {
                    id: "terms",
                    header: "Matched terms",
                    cell: (m) => m.matched_terms.join(", "),
                  },
                  { id: "account", header: "Account", cell: (m) => m.account_id ?? "—" },
                  { id: "profile", header: "Profile", cell: (m) => m.profile ?? "—" },
                  {
                    id: "view",
                    header: "",
                    cell: (m) => (
                      <Button variant="inline-link" onClick={() => setPolicyMatch(m)}>
                        View policy
                      </Button>
                    ),
                  },
                ]}
              />
            </SpaceBetween>
          </Container>
        )}
      </SpaceBetween>

      <Modal
        visible={!!policyMatch}
        size="large"
        onDismiss={() => setPolicyMatch(null)}
        header={policyMatch ? `${policyMatch.service} — policy` : "Policy"}
        footer={
          <Box float="right">
            <Button variant="primary" onClick={() => setPolicyMatch(null)}>
              Close
            </Button>
          </Box>
        }
      >
        {policyMatch && (
          <SpaceBetween size="s">
            <Box variant="small">{policyMatch.resource_arn}</Box>
            <Box variant="code">
              <pre
                style={{
                  margin: 0,
                  maxHeight: "60vh",
                  overflow: "auto",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                }}
              >
                {formatPolicy(policyMatch.policy)}
              </pre>
            </Box>
          </SpaceBetween>
        )}
      </Modal>
    </ContentLayout>
  );
}
