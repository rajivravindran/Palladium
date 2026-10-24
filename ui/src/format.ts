import type { ApprovalStatus, Incident, OperatorAction, River3Event, SessionState, WorkloadState } from "./types";

/** API times are UTC; SQLite returns them without an offset, which Date would read as local time. */
export function parseTime(iso: string): number {
  return new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(iso) ? iso : `${iso}Z`).getTime();
}

export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - parseTime(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(parseTime(iso)).toLocaleDateString();
}

export function clock(iso: string): string {
  return new Date(parseTime(iso)).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export const severityLabel: Record<Incident["severity"], string> = {
  critical: "Critical",
  high: "High",
  info: "Info",
};

export const statusLabel: Record<Incident["status"], string> = {
  open: "Needs review",
  contained: "Contained",
  resolved: "Resolved",
  false_positive: "Not a threat",
};

export const threatLabel: Record<Incident["threat"], string> = {
  agent_drift: "AI agent left its scope",
  external_exploit: "Service behaving outside its scope",
  unknown: "Unclassified",
};

export const stateLabel: Record<WorkloadState, string> = {
  running: "Running",
  frozen: "Frozen",
  terminated: "Terminated",
  unknown: "State unknown",
};

export const kindLabel = {
  ai_worker: "AI worker",
  shared_service: "Shared service",
  unknown: "Unenrolled",
} as const;

export const actionLabel: Record<OperatorAction["action"], string> = {
  resume: "Resume",
  terminate: "Terminate",
  resolve: "Mark resolved",
  false_positive: "Mark not a threat",
  revoke_session: "Revoke session (controller)",
  revoke: "Revoke session",
};

export const sessionStateLabel: Record<SessionState, string> = {
  active: "Active",
  ended: "Ended",
  revoked: "Revoked",
  unknown: "Not registered",
};

export const approvalStatusLabel: Record<ApprovalStatus, string> = {
  pending: "Waiting",
  allowed: "Allowed",
  denied: "Denied",
  expired: "Expired (refused)",
};

/** How an event or incident came to name a session (22 Oct contract §1). */
export const sessionSourceLabel: Record<string, string> = {
  gateway: "reported by the gateway",
  harness: "reported by the agent harness",
  sensor: "reported by the sensor",
  correlated: "correlated by timing (advisory)",
  incident: "from the incident's evidence",
};

/** Operator reasons go in the audit log; the API requires at least this many characters. */
export const MIN_REASON = 8;

export const actionStatusLabel: Record<OperatorAction["status"], string> = {
  requested: "Waiting for the containment layer",
  delivered: "Sent to the containment layer",
  completed: "Done",
  failed: "Failed",
  recorded: "Recorded",
};

/** `revoke` is answered by the session revoker (gateway / identity provider), not the containment layer. */
export function actionStatusText(a: Pick<OperatorAction, "action" | "status">): string {
  if (a.action === "revoke") {
    if (a.status === "requested") return "Waiting for the session revoker";
    if (a.status === "delivered") return "Sent to the session revoker";
  }
  return actionStatusLabel[a.status] ?? a.status;
}

/** One plain-English line per event, built from Channel A facts only. */
export function describeEvent(e: River3Event): { verb: string; object: string } {
  const t = e.facts.target || {};
  const who = e.facts.process?.comm || "a process";
  const outcome = e.outcome === "success" ? "" : e.outcome === "failed" ? " (failed)"
    : e.outcome === "pending" ? " (in progress)" : " (outcome unknown)";
  switch (e.kind) {
    case "file_open":
      return { verb: `${who} opened a file for ${t.access || "access"}${outcome}`, object: t.path || "unknown path" };
    case "process_exec":
      return {
        verb: `${who} started a program${t.binary_class ? ` (${t.binary_class.toLowerCase().replace("_", " ")})` : ""}${outcome}`,
        object: t.exe || "unknown program",
      };
    case "net_connect":
      return { verb: `${who} opened a network connection${outcome}`, object: `${t.ip ?? "?"}:${t.port ?? "?"}` };
  }
}

export function responseLine(inc: Incident): string {
  const r = inc.response || {};
  // `revoke` completed (22 Oct contract §3): the revoker confirmed the session is cut; the incident stays as it was.
  const revoked = r.session_revoked === true
    ? ` Session ${typeof r.revoked_session_id === "string" ? r.revoked_session_id : ""} revoked${typeof r.revoked_by === "string" ? ` at ${r.revoked_by}'s request` : ""}.`
    : "";
  if (r.action) {
    const state = r.state ? `, ${r.state}` : ", state not reported";
    const lat = typeof r.latency_ms === "number" ? ` in ${r.latency_ms.toFixed(1)} ms` : "";
    return `River3 ran “${r.action}”${state}${lat}.${revoked}`;
  }
  if (revoked) return revoked.trim();
  if (inc.mode === "shadow") return "Shadow mode: nothing was done automatically.";
  if (inc.verdict === "unresolved") return "Not enough evidence to act. Alert only.";
  return "No response reported yet.";
}
