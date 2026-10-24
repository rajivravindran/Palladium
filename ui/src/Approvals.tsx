import { useCallback, useEffect, useState } from "react";
import { api, optional } from "./api";
import { ago, approvalStatusLabel, clock, MIN_REASON, parseTime } from "./format";
import { CopyId } from "./IncidentDetail";
import { TierBadge } from "./Workloads";
import type { Approval, Tier, Workload } from "./types";

const TIERS: readonly string[] = ["steady", "rising", "high", "crossed"];
function isTier(s: string): s is Tier {
  return TIERS.includes(s);
}

const RECENT = 30;

/** True once expires_at has passed; an approval without a usable expires_at never expires on screen. */
function isExpired(a: Approval, now: number): boolean {
  if (!a.expires_at) return false;
  const t = parseTime(a.expires_at);
  return !Number.isNaN(t) && t <= now;
}

/** "expires in 1:58" counting down by the second; past expiry the hold reads as refused. */
function countdown(iso: string | undefined, now: number): { text: string; past: boolean; urgent: boolean } {
  if (!iso) return { text: "no expiry", past: false, urgent: false };
  const ms = parseTime(iso) - now;
  if (Number.isNaN(ms)) return { text: "no expiry", past: false, urgent: false };
  const s = Math.max(0, Math.round(Math.abs(ms) / 1000));
  const span = s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
    : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
  return ms <= 0 ? { text: `expired ${ago(iso)}`, past: true, urgent: false }
    : { text: `expires in ${span}`, past: false, urgent: ms < 30_000 };
}

/** The decision shown for a row, with expiry computed on screen too so a stale hold never looks decidable. */
function shownStatus(a: Approval, now: number): Approval["status"] {
  return a.status === "pending" && isExpired(a, now) ? "expired" : a.status;
}

/**
 * The approval gate (22 Oct contract §2). The gateway asks before a tool runs; below tier High the API allows
 * on its own, at High a risky call is HELD here until an operator decides, at Crossed it is denied. Allow/Deny
 * posts a decision; the gateway polls the approval and runs or refuses the tool. Nothing here touches the
 * workload itself, and a hold nobody decides is refused when its countdown ends.
 */
export function Approvals({ token, tick, canAct, onError }: {
  token: string; tick: number; canAct: boolean; onError: (e: unknown) => void;
}) {
  const [rows, setRows] = useState<Approval[] | null>(null);
  const [names, setNames] = useState<Record<string, Workload>>({});
  const [unavailable, setUnavailable] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(() => {
    let alive = true;
    Promise.all([optional(api.approvals(token)), optional(api.workloads(token))])
      .then(([a, w]) => {
        if (!alive) return;
        setUnavailable(a === null);
        setRows(Array.isArray(a) ? a : []);
        if (Array.isArray(w)) setNames(Object.fromEntries(w.map((x) => [x.id, x])));
      })
      .catch(onError);
    return () => {
      alive = false;
    };
  }, [token, onError]);

  // Reload on every stream message (`approval` events among them) and when the stream is down, on the poll.
  useEffect(load, [load, tick]);

  // Countdowns move by the second while something is pending; otherwise a slow clock is enough.
  const hasPending = (rows ?? []).some((a) => a.status === "pending" && !isExpired(a, Date.now()));
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), hasPending ? 1000 : 30_000);
    return () => clearInterval(t);
  }, [hasPending]);

  // A hold that expires on screen should also be reloaded, so the API's lazy sweep records it.
  const pendingCount = (rows ?? []).filter((a) => shownStatus(a, now) === "pending").length;
  useEffect(() => {
    if (rows && rows.some((a) => a.status === "pending" && isExpired(a, now))) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingCount]);

  if (!rows) return <section className="table-pane"><p className="muted">Loading…</p></section>;

  const pending = rows.filter((a) => shownStatus(a, now) === "pending");
  const recent = rows.filter((a) => shownStatus(a, now) !== "pending").slice(0, RECENT);

  return (
    <section className="table-pane approvals" aria-label="Approvals">
      <div className="pane-head">
        <div>
          <h3>Approvals{pending.length > 0 && <span className="count">{pending.length}</span>}</h3>
          <p className="muted small">
            Tool calls the gateway is holding for a human. Below tier High the API allows on its own; at High a risky
            call waits here; at Crossed it is refused. A hold nobody decides is refused when its countdown ends.
            The workload itself is never paused by a hold.
          </p>
        </div>
      </div>

      {unavailable && (
        <p className="muted pad">This API does not expose approvals yet (<code>GET /api/v1/approvals</code> returned 404).</p>
      )}

      {!unavailable && pending.length === 0 && (
        <div className="empty">
          <p className="empty-title">Nothing is waiting for you.</p>
          <p className="muted">
            A hold appears here when a workload at tier High asks for a risky tool, or when its gate (Workloads) holds one.
          </p>
        </div>
      )}

      {pending.length > 0 && (
        <ul className="approval-list">
          {pending.map((a) => (
            <ApprovalRow key={a.id} a={a} workload={names[a.workload_id]} canAct={canAct} token={token} now={now}
              onDecided={load} onError={onError} />
          ))}
        </ul>
      )}

      <div className="section-head recent-head">
        <h3>Recent decisions</h3>
        <span className="muted small">newest first · includes the allows and denies the API decided on its own</span>
      </div>
      {recent.length === 0 ? (
        <p className="muted pad">No decisions recorded yet.</p>
      ) : (
        <table className="recent-decisions">
          <thead>
            <tr>
              <th>When</th>
              <th>Tool</th>
              <th>Workload</th>
              <th>Tier</th>
              <th>Decision</th>
              <th>By</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((a) => {
              const st = shownStatus(a, now);
              return (
                <tr key={a.id} className={`decision-${st}`}>
                  <td className="mono" title={new Date(parseTime(a.decided_at || a.requested_at)).toLocaleString()}>
                    {clock(a.decided_at || a.requested_at)}
                  </td>
                  <td><code>{a.tool}</code>{a.risk === "normal" && <span className="muted small"> normal</span>}</td>
                  <td>{names[a.workload_id]?.name ?? a.workload_id}</td>
                  <td>{isTier(a.tier) ? <TierBadge tier={a.tier} /> : a.tier}</td>
                  <td><span className={`pill approval-status-${st}`}>{approvalStatusLabel[st] ?? st}</span></td>
                  <td>{a.decided_by ?? (st === "expired" ? "nobody" : "–")}</td>
                  <td className="muted small reason-cell">{a.decision_reason || "–"}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ApprovalRow({ a, workload, canAct, token, now, onDecided, onError }: {
  a: Approval; workload?: Workload; canAct: boolean; token: string; now: number;
  onDecided: () => void; onError: (e: unknown) => void;
}) {
  const [pending, setPending] = useState<"allow" | "deny" | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const exp = countdown(a.expires_at, now);
  const status = shownStatus(a, now);
  const open = status === "pending";

  async function decide() {
    if (!pending) return;
    setBusy(true);
    setNote(null);
    try {
      const r = await api.decideApproval(token, a.id, pending, reason.trim());
      setNote(`${approvalStatusLabel[r.status] ?? r.status}${r.decided_by ? ` by ${r.decided_by}` : ""}.`);
      setPending(null);
      setReason("");
      onDecided();
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <li className={`approval approval-${status}`}>
      <div className="approval-main">
        <div className="pills">
          {isTier(a.tier) ? <TierBadge tier={a.tier} /> : <span className="pill">{a.tier || "tier unknown"}</span>}
          <span className={`pill approval-status-${status}`}>{approvalStatusLabel[status] ?? status}</span>
          {a.risk === "risky" ? <span className="tag risky">risky</span> : <span className="tag">normal</span>}
          <span className="muted small">requested {ago(a.requested_at)}{a.requested_by ? ` by ${a.requested_by}` : ""}</span>
          <span className={`countdown${exp.urgent ? " urgent" : ""}${exp.past ? " past" : ""}`} aria-live="off">{exp.text}</span>
        </div>
        <p className="approval-title">
          <code>{a.tool}</code> on <strong>{workload?.name ?? a.workload_id}</strong>
          {workload?.team && <span className="tag team"> {workload.team}</span>}
        </p>
        <div className="untrusted-box" role="note">
          <span className="untrusted-label">From the agent — untrusted</span>
          {a.summary ? <pre className="mono small args">{a.summary}</pre>
            : <p className="muted small">The agent gave no description of this call.</p>}
        </div>
        <p className="muted small ids">
          Session <CopyId value={a.session_id || "–"} label="session id" />
          {a.tool_call_id && <> · tool call <CopyId value={a.tool_call_id} label="tool call id" /></>}
          {a.decided_by && <> · decided by {a.decided_by}{a.decided_at ? ` at ${clock(a.decided_at)}` : ""}</>}
          {a.decision_reason && <> · “{a.decision_reason}”</>}
        </p>
        {note && <p className="note" role="status">{note}</p>}
      </div>
      {open && canAct && (
        <div className="approval-actions">
          {!pending ? (
            <div className="action-buttons">
              <button className="btn primary" onClick={() => setPending("allow")}>Allow</button>
              <button className="btn danger" onClick={() => setPending("deny")}>Deny</button>
            </div>
          ) : (
            <form className="confirm" onSubmit={(e) => { e.preventDefault(); decide(); }}>
              <label htmlFor={`reason-${a.id}`}>Reason to {pending} <code>{a.tool}</code></label>
              <textarea id={`reason-${a.id}`} rows={2} value={reason} autoFocus onChange={(e) => setReason(e.target.value)}
                placeholder={pending === "allow" ? "e.g. expected step of the deploy runbook" : "e.g. not part of this task"} />
              <div className="action-buttons">
                <button type="submit" className={`btn ${pending === "deny" ? "danger" : "primary"}`}
                  disabled={busy || reason.trim().length < MIN_REASON}>
                  {busy ? "Sending…" : pending === "allow" ? "Confirm allow" : "Confirm deny"}
                </button>
                <button type="button" className="btn quiet" onClick={() => setPending(null)} disabled={busy}>Cancel</button>
              </div>
              {reason.trim().length < MIN_REASON && (
                <p className="muted small">A reason of {MIN_REASON}+ characters is required; it goes in the audit log.</p>
              )}
            </form>
          )}
        </div>
      )}
      {open && !canAct && <p className="muted small">Your role can see approvals but not decide them.</p>}
    </li>
  );
}
