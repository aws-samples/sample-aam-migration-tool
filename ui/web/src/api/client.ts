// Tiny fetch wrapper for the Truffle backend API. No client framework — just
// typed helpers around fetch, kept minimal per the design tenets.

export interface WhoAmI {
  profile: string;
  account?: string;
  arn?: string;
  user_id?: string;
  error?: string;
}

export interface CacheWrapper<T = unknown> {
  cached_at?: string;
  data?: T;
}

export interface CacheEntry {
  key: string;
  label: string;
  exists: boolean;
  size_bytes: number;
  cached_at: string | null;
  summary: string;
}

export interface JobProgress {
  completed_units: number;
  total_units: number;
  skipped_units: number;
  message: string;
  activity?: string;
  resources?: number;
  resource_baseline?: number;
}

export interface JobStatus {
  id: string;
  type: string;
  status: "running" | "done" | "error";
  progress: JobProgress;
  started_at: string;
  finished_at: string | null;
  error: string | null;
  result: CacheWrapper | null;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : {};
  if (!res.ok) {
    throw new Error(body?.error || `Request failed (${res.status})`);
  }
  return body as T;
}

export const api = {
  health: () => request<{ status: string }>("/api/health"),
  config: () => request<{ idc_region: string; execution_mode: string }>("/api/config"),

  // Credentials / meta
  profiles: () => request<{ profiles: string[] }>("/api/profiles"),
  whoami: (profile?: string) =>
    request<WhoAmI>(`/api/whoami${profile ? `?profile=${encodeURIComponent(profile)}` : ""}`),

  // Cache management
  cacheOverview: () => request<{ entries: CacheEntry[] }>("/api/cache"),
  cacheClear: (key?: string) =>
    request<{ cleared: string[] }>("/api/cache/clear", {
      method: "POST",
      body: JSON.stringify(key ? { key } : {}),
    }),

  // Policy Analysis (wired, job-based)
  policyServices: () => request<{ services: string[] }>("/api/policy-analysis/services"),
  policyResult: () => request<CacheWrapper>("/api/policy-analysis/result"),
  policyScan: (payload: unknown) =>
    request<{ job_id: string }>("/api/policy-analysis/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  policyStatus: (jobId: string) =>
    request<JobStatus>(`/api/policy-analysis/status?job_id=${encodeURIComponent(jobId)}`),

  // IAM Federation -> AAM (wired)
  iamProviders: (payload: unknown) =>
    request<{ providers: { arn: string; name: string; account_id: string; label: string; is_identity_center: boolean }[] }>(
      "/api/iam-federation/providers",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  iamDiscover: (payload: unknown) =>
    request<{ job_id: string }>("/api/iam-federation/discover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  iamDiscoverStatus: (jobId: string) =>
    request<JobStatus>(`/api/iam-federation/discover/status?job_id=${encodeURIComponent(jobId)}`),
  iamState: () => request<CacheWrapper>("/api/iam-federation/state"),
  iamMigrate: (payload: unknown) =>
    request<{ total: number; results: unknown[]; summary: { total: number; success: number; skipped: number; error: number; mode: string } }>(
      "/api/iam-federation/migrate",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  iamGenerateIac: (payload: unknown) =>
    request<{ roles_count: number; cloudformation: { path: string; content: string }; terraform: { path: string; content: string } }>(
      "/api/iam-federation/generate-iac",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  iamLog: () => request<CacheWrapper>("/api/iam-federation/log"),

  // IdC -> AAM (wired)
  idcState: () => request<CacheWrapper>("/api/idc/state"),
  idcDiscover: (payload: unknown) =>
    request<{ job_id: string }>("/api/idc/discover", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  idcDiscoverStatus: (jobId: string) =>
    request<JobStatus>(`/api/idc/discover/status?job_id=${encodeURIComponent(jobId)}`),
  idcGenerateIac: (payload: unknown) =>
    request<{ roles_count: number; entitlements_count: number; templates: Record<string, { path: string; content: string }>; accounts: string[]; role_map: Record<string, string> }>(
      "/api/idc/generate-iac",
      { method: "POST", body: JSON.stringify(payload) }
    ),
  idcApply: (payload: unknown) =>
    request<{ job_id: string }>("/api/idc/apply", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  idcApplyStatus: (jobId: string) =>
    request<JobStatus>(`/api/idc/apply/status?job_id=${encodeURIComponent(jobId)}`),
};
