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

  // IAM Federation -> AAM (skeleton)
  iamState: () => request<CacheWrapper>("/api/iam-federation/state"),
  iamImportEntitlements: (entitlements: unknown) =>
    request<CacheWrapper>("/api/iam-federation/entitlements", {
      method: "POST",
      body: JSON.stringify({ entitlements }),
    }),
  iamMigrate: (payload: unknown) =>
    request<unknown>("/api/iam-federation/migrate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // IdC -> AAM (skeleton)
  idcState: () => request<CacheWrapper>("/api/idc/state"),
  idcDiscover: (profile: string) =>
    request<CacheWrapper>("/api/idc/discover", {
      method: "POST",
      body: JSON.stringify({ profile }),
    }),
};
