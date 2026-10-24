export type WorkloadState = "running" | "frozen" | "terminated" | "unknown";

export interface Workload {
  id: string;
  name: string;
  profile: string;
  kind: "ai_worker" | "shared_service" | "unknown";
  sensor: string;
  state: WorkloadState;
  labels: Record<string, string>;
  demo: boolean;
  enrolled_at: string;
  updated_at: string;
  /** owning team (CONTRACTS §6); "" or absent = unassigned */
  team?: string;
}

export interface River3Event {
  id: string;
  workload_id: string;
  kind: "file_open" | "process_exec" | "net_connect";
  outcome: "success" | "failed" | "pending" | "unknown";
  ts: string;
  facts: {
    process?: { pid?: number; ppid?: number; uid?: number; comm?: string };
    target?: {
      path?: string; access?: string; exe?: string; binary_class?: string; ip?: string; port?: number;
    };
    errno?: number;
    [k: string]: unknown;
  };
  payload: { argv?: string[]; [k: string]: unknown };
}

export interface OperatorAction {
  id: string;
  incident_id: string;
  workload_id: string;
  action: "resume" | "terminate" | "resolve" | "false_positive" | "revoke_session" | "revoke";
  /** `revoke` (22 Oct contract): the session the request targets; otherwise the incident's binding */
  session_id?: string | null;
  operator: string;
  reason: string;
  status: "requested" | "delivered" | "completed" | "failed" | "recorded";
  result: Record<string, unknown>;
  requested_at: string;
  completed_at: string | null;
}

export interface Summary {
  id: string;
  source: "model" | "fallback";
  model: string;
  content: {
    headline: string;
    timeline: { event_id: string; what: string }[];
    assessment: string;
    unknowns: string[];
  };
  grounded: boolean;
  invalid_citations: string[];
  latency_ms: number;
  created_at: string;
}

export interface Incident {
  id: string;
  workload: Workload;
  title: string;
  threat: "agent_drift" | "external_exploit" | "unknown";
  severity: "info" | "high" | "critical";
  verdict: "prohibited" | "unresolved";
  rule: string;
  reason: string;
  mode: "shadow" | "active";
  status: "open" | "contained" | "resolved" | "false_positive";
  response: { action?: string; state?: string; latency_ms?: number; [k: string]: unknown };
  policy: Partial<PolicyDecision>;
  demo: boolean;
  created_at: string;
  updated_at: string;
  event_count: number;
  /** the agent session that was acting (CONTRACTS §1.3); absent when no event carried one */
  session_id?: string;
  /**
   * 22 Oct contract §1: the first event's `facts.session`, or the evidence-bound session_id
   * (source "incident"). `correlated` means the API attributed the event to a recent agent-log
   * tool call by timing alone: advisory, shown as such.
   */
  session?: SessionRef | null;
  events?: River3Event[];
  actions?: OperatorAction[];
  summaries?: Summary[];
}

export type SessionSource = "gateway" | "harness" | "sensor" | "correlated" | "incident";

/** Who was acting, as stamped on an event or an incident (22 Oct contract §1). */
export interface SessionRef {
  id: string;
  tool_call_id?: string | null;
  source?: SessionSource | string | null;
}

export type SessionState = "active" | "ended" | "revoked" | "unknown";

/** One agent run as the gateway identified it, bound to a workload (CONTRACTS §1). */
export interface SessionInfo {
  id: string;
  workload_id: string;
  principal: string;
  state: SessionState;
  started_at: string;
  ended_at?: string | null;
  revoked_at?: string | null;
  revoked_by?: string | null;
  revoke_reason?: string | null;
  labels?: Record<string, string>;
  last_seen_at?: string | null;
  /** incident ids on GET /sessions/{id} */
  incident_ids?: string[];
  /** false when the gateway never registered the id and it is known only from evidence */
  registered?: boolean;
}

export type ApprovalStatus = "pending" | "allowed" | "denied" | "expired";

/**
 * One tool call the gateway asked about (22 Oct contract §2). `allowed`/`denied` by policy are recorded
 * with decided_by "policy"; a `pending` hold waits for an operator until expires_at, then reads expired
 * (which the gateway treats as deny).
 */
export interface Approval {
  id: string;
  workload_id: string;
  session_id: string;
  tool: string;
  tool_call_id?: string | null;
  risk: "normal" | "risky";
  /** Channel B: what the agent says it is about to do. Untrusted; render as such. */
  summary: string;
  summary_trust?: "untrusted";
  tier_at_request: string;
  /** same as tier_at_request (kept for the tier badge) */
  tier: string;
  status: ApprovalStatus;
  decision_reason?: string | null;
  requested_by?: string | null;
  requested_at: string;
  expires_at: string;
  decided_by?: string | null;
  decided_at?: string | null;
}

export type HoldAt = "never" | "rising" | "high";

/** Per-workload approval gate, outside the engine profile (CONTRACTS §3.1). */
export interface GateConfig {
  risky_tools: string[];
  hold_at: HoldAt;
  ttl_s: number;
}

export interface Me {
  operator: string;
  role: string;
  permissions: string[];
  /** operator's teams (CONTRACTS §6); absent or empty = all teams */
  teams?: string[];
}

export interface Stats {
  open: number;
  contained: number;
  critical_open: number;
  workloads: number;
  frozen: number;
  pending_actions: number;
  /** workloads whose early-warning tier is rising or high */
  heading_out: number;
  /** approvals waiting for an operator; absent on an API without the gate */
  pending_approvals?: number;
}

export type Tier = "steady" | "rising" | "high" | "crossed";

export interface DriftReason {
  source: "kernel" | "agent_log" | "model";
  tier: Tier;
  text: string;
  evidence: Record<string, unknown>;
}

/** Early-warning state of one workload. Agent-log and model sources only ever raise the tier. */
export interface DriftState {
  workload_id: string;
  tier: Tier;
  previous_tier: Tier | null;
  trend: "up" | "down" | "flat";
  reasons: DriftReason[];
  features: {
    kernel?: { window_min: number; events: number; failed: number; refused: number; new_resources: number;
      new_destinations: number; shared_writes: number; baseline_events: number };
    agent_log?: { entries: number; injection_markers: number; workaround_markers: number; retry_streak: number; unlogged: number };
  };
  model: { name: string | null; answer: string | null; chunks?: number; per_chunk?: string[] };
  computed_at: string;
  changed_at: string;
}

export interface DriftPoint {
  tier: Tier;
  at: string;
  summary: string;
}

export interface DriftDetail {
  state: DriftState | null;
  history: DriftPoint[];
  log_entries: number;
}

/** A line of the agent's OWN log. Untrusted: the agent wrote it. */
export interface AgentLogEntry {
  id: string;
  workload_id: string;
  session: string;
  ts: string;
  kind: "tool_call" | "tool_result" | "plan" | "reasoning" | "message" | "text";
  tool: string;
  status: "ok" | "error" | "";
  target: string;
  text: string;
  received_at: string;
  trust: "untrusted";
}

export interface AuditRow {
  id: string;
  ts: string;
  actor: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
}

/** Policy engine decision stored on an incident. `action` is at most an eligible candidate. */
export interface PolicyDecision {
  profile_name: string;
  profile_version: number;
  status: "IN_SCOPE" | "VIOLATION" | "REVIEW" | "UNKNOWN";
  findings: { code: string; rule?: string }[];
  recommended_action: "NONE" | "ALERT" | "PAUSE_CONTAINER" | "REVOKE_SESSION";
  action: "NONE" | "ALERT" | "PAUSE_CONTAINER" | "REVOKE_SESSION";
  blockers: string[];
  candidate: Record<string, unknown> | null;
}

export type ExecClass = "DIAGNOSTIC" | "INTERPRETER" | "NET_CLIENT" | "PRIVILEGED_TOOL" | "OTHER";
export type ResponseAction = "ALERT" | "PAUSE_CONTAINER" | "REVOKE_SESSION";

/** A policy profile exactly as the policy engine loads it (policy/profile.go). */
export interface ProfileBody {
  name: string;
  kind: "ai_worker" | "shared_service";
  description: string;
  version?: number | null;
  mode: "SHADOW_MODE" | "ACTIVE_FREEZE_MODE";
  decoys: string[];
  protected_read: string[];
  /** null = reads are not restricted; [] = no reads outside decoys/protected paths */
  read_allowed: string[] | null;
  write_allowed: string[];
  exec_allowed_classes: ExecClass[];
  exec_denied_classes: ExecClass[];
  egress_allowed: string[];
  /**
   * Hostnames (optionally `*.example.com`) the controller resolves every 60 s into egress_allowed.
   * The engine never matches on them. Absent on profiles saved before the field existed.
   */
  egress_allowed_domains?: string[];
  response: { on_violation: ResponseAction; on_structural_guard: ResponseAction };
}

export interface PolicyProfile {
  name: string;
  kind: ProfileBody["kind"];
  version: number;
  body: ProfileBody;
  updated_by: string;
  created_at: string;
  updated_at: string;
  workloads?: number;
}

export interface PolicyVersion {
  id: string;
  name: string;
  version: number;
  body: ProfileBody;
  deleted: boolean;
  author: string;
  comment: string;
  created_at: string;
}

export interface ControllerSync {
  controller: string;
  seen_revision: string;
  active_revision: string;
  profiles: number;
  error: string;
  reported_at: string;
  current: boolean;
}

export interface PolicyList {
  revision: string;
  profiles: PolicyProfile[];
  controllers: ControllerSync[];
  /** profile names workloads are assigned to that no policy defines */
  unbound: string[];
}

export interface PolicyDetail {
  profile: PolicyProfile | null;
  history: PolicyVersion[];
  workloads: Workload[];
}

export interface FieldError {
  field: string;
  message: string;
}
