import type {
  AgentLogEntry, Approval, AuditRow, DriftDetail, DriftState, FieldError, GateConfig, Incident, Me, OperatorAction,
  PolicyDetail, PolicyList, PolicyProfile, ProfileBody, SessionInfo, Stats, Summary, Workload,
} from "./types";

const KEY = "river3.operatorToken";

export function loadToken(): string | null {
  try {
    return sessionStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function saveToken(token: string | null) {
  try {
    if (token) sessionStorage.setItem(KEY, token);
    else sessionStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: token lives in memory only */
  }
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public fields: FieldError[] = []) {
    super(message);
  }
}

async function call<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(init.headers || {}) },
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    let fields: FieldError[] = [];
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail)) msg = body.detail.map((d: { msg: string }) => d.msg).join("; ");
      else if (body.detail && typeof body.detail.message === "string") {
        msg = body.detail.message;
        fields = Array.isArray(body.detail.errors) ? body.detail.errors : [];
      }
    } catch {
      /* keep status text */
    }
    throw new ApiError(res.status, msg, fields);
  }
  return res.json() as Promise<T>;
}

/**
 * Treat a 404 (or 405 from an API built before the endpoint existed) as "nothing there" so a
 * screen can render its empty state instead of an error banner. Every other failure propagates.
 */
export async function optional<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

export const api = {
  me: (t: string) => call<Me>(t, "/api/v1/me"),
  stats: (t: string) => call<Stats>(t, "/api/v1/stats"),
  incidents: (t: string, status?: string) =>
    call<Incident[]>(t, `/api/v1/incidents${status ? `?status=${status}` : ""}`),
  incident: (t: string, id: string) => call<Incident>(t, `/api/v1/incidents/${id}`),
  workloads: (t: string) => call<Workload[]>(t, "/api/v1/workloads"),
  audit: (t: string) => call<AuditRow[]>(t, "/api/v1/audit"),
  act: (t: string, id: string, action: OperatorAction["action"], reason: string) =>
    call<OperatorAction>(t, `/api/v1/incidents/${id}/actions`, {
      method: "POST",
      body: JSON.stringify({ action, reason }),
    }),
  session: (t: string, id: string) => call<SessionInfo>(t, `/api/v1/sessions/${encodeURIComponent(id)}`),
  approvals: (t: string, status?: Approval["status"] | string, limit = 200) =>
    call<Approval[]>(t, `/api/v1/approvals?limit=${limit}${status ? `&status=${status}` : ""}`),
  decideApproval: (t: string, id: string, decision: "allow" | "deny", reason: string) =>
    call<Approval>(t, `/api/v1/approvals/${encodeURIComponent(id)}/decide`, {
      method: "POST",
      body: JSON.stringify({ decision, reason }),
    }),
  gate: (t: string, workloadId: string) => call<GateConfig>(t, `/api/v1/workloads/${encodeURIComponent(workloadId)}/gate`),
  saveGate: (t: string, workloadId: string, body: GateConfig) =>
    call<GateConfig>(t, `/api/v1/workloads/${encodeURIComponent(workloadId)}/gate`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  policies: (t: string) => call<PolicyList>(t, "/api/v1/policies"),
  policy: (t: string, name: string) => call<PolicyDetail>(t, `/api/v1/policies/${encodeURIComponent(name)}`),
  validatePolicy: (t: string, body: unknown) =>
    call<{ ok: boolean; errors: FieldError[]; profile: ProfileBody | null }>(t, "/api/v1/policies/validate", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  savePolicy: (t: string, body: ProfileBody, baseVersion: number, comment: string) =>
    call<PolicyProfile>(t, `/api/v1/policies/${encodeURIComponent(body.name)}`, {
      method: "PUT",
      body: JSON.stringify({ profile: body, base_version: baseVersion, comment }),
    }),
  deletePolicy: (t: string, name: string, baseVersion: number, comment: string) =>
    call<{ deleted: string }>(t, `/api/v1/policies/${encodeURIComponent(name)}`, {
      method: "DELETE",
      body: JSON.stringify({ base_version: baseVersion, comment }),
    }),
  drift: (t: string) => call<DriftState[]>(t, "/api/v1/drift"),
  driftFor: (t: string, workloadId: string) => call<DriftDetail>(t, `/api/v1/drift/${encodeURIComponent(workloadId)}`),
  recomputeDrift: (t: string, workloadId: string) =>
    call<DriftState>(t, `/api/v1/drift/${encodeURIComponent(workloadId)}/recompute`, { method: "POST" }),
  agentLog: (t: string, workloadId: string, limit = 50) =>
    call<AgentLogEntry[]>(t, `/api/v1/agents/${encodeURIComponent(workloadId)}/log?limit=${limit}`),
  summarize: (t: string, id: string) =>
    call<Summary>(t, `/api/v1/incidents/${id}/summary`, { method: "POST" }),
  /** Swaps the operator token for a 60-second, single-use ticket so the token never appears in a URL. */
  stream: async (t: string) => {
    const { ticket } = await call<{ ticket: string }>(t, "/api/v1/stream/ticket", { method: "POST" });
    return new EventSource(`/api/v1/stream?ticket=${encodeURIComponent(ticket)}`);
  },
};
