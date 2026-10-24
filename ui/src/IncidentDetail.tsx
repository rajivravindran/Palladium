import { useEffect, useState } from "react";
import { api, optional } from "./api";
import {
  actionLabel, actionStatusText, ago, clock, describeEvent, kindLabel, MIN_REASON, responseLine,
  sessionSourceLabel, sessionStateLabel, severityLabel, stateLabel, statusLabel, threatLabel,
} from "./format";
import type { Incident, OperatorAction, SessionInfo, Summary } from "./types";

/** Monospace, selectable, with a copy button (clipboard may be unavailable: then selecting still works). */
export function CopyId({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      /* no clipboard permission: the text is selectable */
    }
  }
  return (
    <span className="copy-id">
      <code className="mono selectable" title={label}>{value}</code>
      <button type="button" className="btn quiet tiny" onClick={copy} aria-label={`Copy ${label}`}>{done ? "Copied" : "Copy"}</button>
    </span>
  );
}

type Action = OperatorAction["action"];

export function IncidentDetail({
  token, incidentId, onChanged, onError,
}: {
  token: string;
  incidentId: string | null;
  onChanged: () => void;
  onError: (e: unknown) => void;
}) {
  const [inc, setInc] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [pending, setPending] = useState<Action | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [summarizing, setSummarizing] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  // null = not looked up or unknown to the API (404); the id alone is still shown.
  const [sess, setSess] = useState<SessionInfo | null>(null);

  async function load() {
    if (!incidentId) return;
    setLoading(true);
    try {
      const i = await api.incident(token, incidentId);
      setInc(i);
      const sid = i.session?.id || i.session_id;
      if (sid) {
        // Best effort: an API without sessions, or a session it never saw, leaves the badge off.
        optional(api.session(token, sid)).then((x) => setSess(x && x.state ? x : null)).catch(() => setSess(null));
      } else {
        setSess(null);
      }
    } catch (e) {
      onError(e);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId, token]);

  if (!incidentId) {
    return (
      <section className="detail-pane empty" aria-label="Incident detail">
        <p className="empty-title">Select an incident</p>
        <p className="muted">Pick one from the list to see what happened and decide what to do.</p>
      </section>
    );
  }
  if (!inc) {
    return (
      <section className="detail-pane" aria-label="Incident detail">
        <p className="muted">{loading ? "Loading…" : "Incident not found."}</p>
      </section>
    );
  }

  const w = inc.workload;
  const canResume = w.state === "frozen";
  const canTerminate = w.state !== "terminated";
  const isOpen = inc.status === "open" || inc.status === "contained";
  // 22 Oct contract §1: the incident's `session` (first event that carries one, correlated included), else
  // the evidence-bound session_id. Revoke targets the same id the API would resolve; it never guesses one.
  const sessionRef = inc.session ?? (inc.session_id ? { id: inc.session_id, source: "incident" } : null);
  const sessionId = sessionRef?.id || null;
  const revoked = sess?.state === "revoked" || inc.response?.session_revoked === true;
  const revokePending = (inc.actions ?? []).some((a) => a.action === "revoke" && (a.status === "requested" || a.status === "delivered"));
  const canRevoke = !!sessionId && !revoked && !revokePending;
  const revokeTitle = !sessionId ? "No session is known for this incident or its workload; nothing to revoke"
    : revoked ? "This session is already revoked"
    : revokePending ? "A revoke request is already on its way to the session revoker"
    : "Ask the session revoker (gateway / identity provider) to cut this agent session; the container keeps running";
  const reasonOk = reason.trim().length >= MIN_REASON;

  async function confirm() {
    if (!pending || !inc) return;
    setBusy(true);
    setNote(null);
    try {
      const a = await api.act(token, inc.id, pending, reason.trim());
      setNote(`${actionLabel[a.action] ?? a.action}: ${actionStatusText(a).toLowerCase()}.`);
      setPending(null);
      setReason("");
      await load();
      onChanged();
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  async function summarize() {
    if (!inc) return;
    setSummarizing(true);
    try {
      const s = await api.summarize(token, inc.id);
      setInc({ ...inc, summaries: [s, ...(inc.summaries ?? [])] });
    } catch (e) {
      onError(e);
    } finally {
      setSummarizing(false);
    }
  }

  const latestSummary = inc.summaries?.[0];

  return (
    <section className="detail-pane" aria-label="Incident detail">
      <header className="detail-head">
        <div className="pills">
          <span className={`sev-pill sev-${inc.severity}`}>{severityLabel[inc.severity]}</span>
          <span className="pill">{statusLabel[inc.status]}</span>
          {inc.mode === "shadow" && <span className="tag">Shadow</span>}
          {inc.demo && <span className="tag demo">Demo</span>}
        </div>
        <h2>{inc.title}</h2>
        <p className="muted">
          {threatLabel[inc.threat]} · rule <code>{inc.rule}</code> · {ago(inc.created_at)}
        </p>
      </header>

      <div className="detail-grid">
        <dl className="facts">
          <dt>Workload</dt>
          <dd>
            {w.name} <span className="muted">({kindLabel[w.kind]}, profile <code>{w.profile}</code>)</span>
          </dd>
          <dt>State</dt>
          <dd><span className={`state-dot state-${w.state}`}>{stateLabel[w.state]}</span></dd>
          <dt>Session</dt>
          <dd>
            {sessionId && sessionRef ? (
              <div className="session-line">
                <CopyId value={sessionId} label="session id" />
                {sess && sess.state !== "unknown" && (
                  <>
                    {sess.principal && <span> · {sess.principal}</span>}
                    {" "}
                    <span className={`pill session-${sess.state}`}>{sessionStateLabel[sess.state] ?? sess.state}</span>
                    {sess.state === "revoked" && sess.revoked_by && <span className="muted small"> by {sess.revoked_by}</span>}
                  </>
                )}
                {inc.response?.session_revoked === true && (!sess || sess.state !== "revoked") && (
                  <span className="pill session-revoked">Revoked</span>
                )}
                {sessionRef.source && (
                  <span className={`tag${sessionRef.source === "correlated" ? " advisory" : ""}`}
                    title={sessionRef.source === "correlated"
                      ? "Attributed by timing to the agent's most recent logged tool call. Nothing vouched for it; check before acting on it."
                      : undefined}>
                    {sessionSourceLabel[sessionRef.source] ?? sessionRef.source}
                  </span>
                )}
                {sessionRef.tool_call_id && (
                  <span className="muted small">tool call <CopyId value={sessionRef.tool_call_id} label="tool call id" /></span>
                )}
              </div>
            ) : (
              <span className="muted">None known. No event named a session and the gateway registered none for this workload.</span>
            )}
          </dd>
          <dt>Why it was flagged</dt>
          <dd>{inc.reason}</dd>
          <dt>Automatic response</dt>
          <dd>{responseLine(inc)}</dd>
          {inc.policy?.status && (
            <>
              <dt>Policy</dt>
              <dd>
                {inc.policy.status}
                {inc.policy.recommended_action && <> · recommends {inc.policy.recommended_action}</>}
                {inc.policy.blockers && inc.policy.blockers.length > 0 && (
                  <span className="muted"> · blocked by {inc.policy.blockers.join(", ")}</span>
                )}
              </dd>
            </>
          )}
        </dl>

        <div className="actions-card">
          <h3>Operator actions</h3>
          {!pending ? (
            <div className="action-buttons">
              <button className="btn" disabled={!canResume} onClick={() => setPending("resume")} title={canResume ? "" : "Only frozen workloads can be resumed"}>
                {actionLabel.resume}
              </button>
              <button className="btn danger" disabled={!canTerminate} onClick={() => setPending("terminate")}>
                {actionLabel.terminate}
              </button>
              <button className="btn danger" disabled={!canRevoke} onClick={() => setPending("revoke")} title={revokeTitle}>
                {actionLabel.revoke}
              </button>
              <button className="btn" disabled={!isOpen} onClick={() => setPending("resolve")}>
                {actionLabel.resolve}
              </button>
              <button className="btn" disabled={!isOpen} onClick={() => setPending("false_positive")}>
                {actionLabel.false_positive}
              </button>
            </div>
          ) : (
            <form
              className="confirm"
              onSubmit={(e) => {
                e.preventDefault();
                confirm();
              }}
            >
              <p>
                <strong>{actionLabel[pending]}</strong> on <strong>{w.name}</strong>
                {(pending === "revoke" || pending === "revoke_session") && sessionId && <> (session <code className="mono">{sessionId}</code>)</>}. This is recorded in the audit log under your name.
              </p>
              {pending === "revoke" && sessionRef?.source === "correlated" && (
                <p className="form-error small">
                  This session was correlated by timing, not reported by the gateway. Confirm it is the right one before revoking.
                </p>
              )}
              <label htmlFor="reason">Reason</label>
              <textarea id="reason" rows={2} value={reason} onChange={(e) => setReason(e.target.value)} autoFocus
                placeholder="Why are you taking this action?" />
              <div className="action-buttons">
                <button type="submit" className={`btn ${pending === "terminate" || pending === "revoke_session" || pending === "revoke" ? "danger" : "primary"}`}
                  disabled={busy || !reasonOk}>
                  {busy ? "Sending…" : `Confirm ${actionLabel[pending].toLowerCase()}`}
                </button>
                <button type="button" className="btn quiet" onClick={() => setPending(null)} disabled={busy}>Cancel</button>
              </div>
              {!reasonOk && <p className="muted small">A reason of {MIN_REASON}+ characters is required.</p>}
            </form>
          )}
          {note && <p className="note" role="status">{note}</p>}

          {inc.actions && inc.actions.length > 0 && (
            <ul className="history">
              {inc.actions.map((a) => (
                <li key={a.id}>
                  <span className="mono">{clock(a.requested_at)}</span> {actionLabel[a.action] ?? a.action} by {a.operator}
                  {a.action === "revoke" && a.session_id && <> (<code className="mono">{a.session_id}</code>)</>}
                  <span className={`act-status act-${a.status}`}> — {actionStatusText(a)}</span>
                  {a.reason && <span className="muted"> · “{a.reason}”</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      <section className="summary-card">
        <div className="section-head">
          <h3>Summary</h3>
          <button className="btn quiet" onClick={summarize} disabled={summarizing}>
            {summarizing ? "Summarizing…" : latestSummary ? "Regenerate" : "Generate summary"}
          </button>
        </div>
        {latestSummary ? <SummaryView s={latestSummary} /> : (
          <p className="muted">No summary yet. A summary is built only from the recorded events below.</p>
        )}
      </section>

      <section className="events">
        <h3>
          Events <span className="muted">({inc.event_count})</span>
        </h3>
        {!inc.events || inc.events.length === 0 ? (
          <p className="muted">No events attached to this incident.</p>
        ) : (
          <ol className="timeline">
            {inc.events.map((e) => {
              const d = describeEvent(e);
              return (
                <li key={e.id} className={`ev ev-${e.kind} out-${e.outcome}`}>
                  <span className="mono ev-time">{clock(e.ts)}</span>
                  <span className="ev-body">
                    <span className="ev-verb">{d.verb}</span>
                    <code className="ev-object">{d.object}</code>
                    {e.payload?.argv && e.payload.argv.length > 0 && (
                      <code className="ev-argv">{e.payload.argv.join(" ")}</code>
                    )}
                  </span>
                </li>
              );
            })}
          </ol>
        )}
      </section>
    </section>
  );
}

function SummaryView({ s }: { s: Summary }) {
  return (
    <div className="summary">
      <p className="headline">{s.content.headline}</p>
      {s.content.timeline.length > 0 && (
        <ol className="summary-timeline">
          {s.content.timeline.map((t, i) => <li key={`${t.event_id}-${i}`}>{t.what}</li>)}
        </ol>
      )}
      <p>{s.content.assessment}</p>
      {s.content.unknowns.length > 0 && (
        <>
          <p className="muted small">Still unknown:</p>
          <ul className="unknowns">{s.content.unknowns.map((u, i) => <li key={i}>{u}</li>)}</ul>
        </>
      )}
      <p className="muted small">
        {s.source === "model" ? `Model: ${s.model}` : "Fallback summary (no model)"} · {s.latency_ms.toFixed(0)} ms ·{" "}
        {s.grounded ? "every claim cites a recorded event" : `${s.invalid_citations.length} citation(s) could not be verified`}
      </p>
    </div>
  );
}
