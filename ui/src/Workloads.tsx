import { useCallback, useEffect, useState } from "react";
import { api, ApiError, optional } from "./api";
import { ago, clock, kindLabel, parseTime, stateLabel } from "./format";
import { inTeam, TeamSelect, teamOptions } from "./TeamSelect";
import type { AgentLogEntry, DriftDetail, DriftReason, DriftState, GateConfig, HoldAt, Tier, Workload } from "./types";

export const tierLabel: Record<Tier, string> = {
  steady: "Steady",
  rising: "Rising",
  high: "High",
  crossed: "Crossed",
};

const tierMeaning: Record<Tier, string> = {
  steady: "Working inside its task.",
  rising: "Its pattern is moving away from its task. The owning team should look.",
  high: "Strong signs it is working around its limits. Risky tools should need a human.",
  crossed: "A kernel-confirmed scope violation is open. See Incidents.",
};

const sourceLabel: Record<DriftReason["source"], string> = {
  kernel: "Kernel facts",
  agent_log: "Agent's own log",
  model: "Model",
};

export function TierBadge({ tier, trend }: { tier: Tier; trend?: DriftState["trend"] }) {
  const arrow = trend === "up" ? " ↑" : trend === "down" ? " ↓" : "";
  return (
    <span className={`tier tier-${tier}`} title={tierMeaning[tier]}>
      {tierLabel[tier]}{arrow}
    </span>
  );
}

export function Workloads({ token, tick, canAct, canEditGate, team, teams, onTeam, onError }: {
  token: string; tick: number; canAct: boolean;
  /** permission `policies`: may edit the per-workload approval gate */
  canEditGate: boolean;
  /** team filter shared with Incidents; "" = all */
  team: string; teams: string[]; onTeam: (t: string) => void;
  onError: (e: unknown) => void;
}) {
  const [rows, setRows] = useState<Workload[] | null>(null);
  const [drift, setDrift] = useState<Record<string, DriftState>>({});
  const [selected, setSelected] = useState<string | null>(null);

  const load = useCallback(() => {
    let alive = true;
    Promise.all([api.workloads(token), api.drift(token)])
      .then(([w, d]) => {
        if (!alive) return;
        setRows(w);
        setDrift(Object.fromEntries(d.map((s) => [s.workload_id, s])));
      })
      .catch(onError);
    return () => {
      alive = false;
    };
  }, [token, onError]);

  useEffect(load, [load, tick]);

  if (!rows) return <section className="table-pane"><p className="muted">Loading…</p></section>;
  if (rows.length === 0) {
    return (
      <section className="table-pane empty">
        <p className="empty-title">No workloads enrolled.</p>
        <p className="muted">Workloads appear once a sensor enrolls them.</p>
      </section>
    );
  }

  const chosen = selected ? rows.find((w) => w.id === selected) ?? null : null;
  const options = teamOptions(teams, rows);
  const shown = rows.filter((w) => inTeam(w, team));
  const anyTeam = options.length > 0;

  return (
    <div className={chosen ? "split" : ""}>
      <section className="table-pane" aria-label="Workloads">
        {anyTeam && (
          <div className="table-tools">
            <TeamSelect id="team-workloads" teams={options} value={team} onChange={onTeam} />
            <span className="muted small">{shown.length} of {rows.length}</span>
          </div>
        )}
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Early warning</th>
              <th>State</th>
              {anyTeam && <th className="wide">Team</th>}
              <th className="wide">Kind</th>
              <th className="wide">Profile</th>
              <th className="wide">Sensor</th>
              <th className="wide">Updated</th>
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 && (
              <tr><td colSpan={8} className="muted">No workloads in this team.</td></tr>
            )}
            {shown.map((w) => {
              const d = drift[w.id];
              return (
                <tr key={w.id} className={`selectable${selected === w.id ? " selected" : ""}`}
                    onClick={() => setSelected(selected === w.id ? null : w.id)}>
                  <td>
                    {w.name} {w.demo && <span className="tag demo">Demo</span>}
                  </td>
                  <td>
                    {d ? <TierBadge tier={d.tier} trend={d.trend} /> : <span className="muted">No reading yet</span>}
                    {d && d.reasons.length > 0 && <span className="muted small"> · {d.reasons.length} reason{d.reasons.length === 1 ? "" : "s"}</span>}
                  </td>
                  <td><span className={`state-dot state-${w.state}`}>{stateLabel[w.state]}</span></td>
                  {anyTeam && <td className="wide">{w.team || <span className="muted">–</span>}</td>}
                  <td className="wide">{kindLabel[w.kind] ?? w.kind}</td>
                  <td className="wide"><code>{w.profile}</code></td>
                  <td className="wide mono">{w.sensor}</td>
                  <td className="wide muted">{ago(w.updated_at)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
      {chosen && (
        <DriftPanel key={chosen.id} token={token} workload={chosen} tick={tick} canAct={canAct} canEditGate={canEditGate}
                    onError={onError} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function DriftPanel({ token, workload, tick, canAct, canEditGate, onError, onClose }: {
  token: string; workload: Workload; tick: number; canAct: boolean; canEditGate: boolean;
  onError: (e: unknown) => void; onClose: () => void;
}) {
  const [detail, setDetail] = useState<DriftDetail | null>(null);
  const [log, setLog] = useState<AgentLogEntry[]>([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    Promise.all([api.driftFor(token, workload.id), api.agentLog(token, workload.id, 30)])
      .then(([d, l]) => {
        if (!alive) return;
        setDetail(d);
        setLog(l);
      })
      .catch(onError);
    return () => {
      alive = false;
    };
  }, [token, workload.id, tick, onError]);

  async function recompute() {
    setBusy(true);
    try {
      const s = await api.recomputeDrift(token, workload.id);
      setDetail((d) => (d ? { ...d, state: s } : { state: s, history: [], log_entries: 0 }));
    } catch (e) {
      onError(e);
    } finally {
      setBusy(false);
    }
  }

  const s = detail?.state ?? null;
  const k = s?.features.kernel;
  const a = s?.features.agent_log;

  return (
    <section className="detail drift-panel" aria-label={`Early warning for ${workload.name}`}>
      <div className="detail-head">
        <div>
          <h2>{workload.name}</h2>
          <p className="muted">
            Early warning · {s ? <TierBadge tier={s.tier} trend={s.trend} /> : "no reading yet"}
            {s && <> · assessed {ago(s.computed_at)}</>}
            {workload.team && <> · team <strong>{workload.team}</strong></>}
          </p>
        </div>
        <div className="pills">
          {canAct && <button className="btn" onClick={recompute} disabled={busy}>{busy ? "Assessing…" : "Assess now"}</button>}
          <button className="btn quiet" onClick={onClose}>Close</button>
        </div>
      </div>

      {!detail && <p className="muted">Loading…</p>}

      {s && (
        <>
          <p>{tierMeaning[s.tier]}</p>
          {detail && detail.history.length > 0 && <TrendLine points={detail.history} />}

          <div className="card">
            <h3>Why</h3>
            {s.reasons.length === 0 && <p className="muted">Nothing stands out in the last {k?.window_min ?? 10} minutes.</p>}
            <ul className="plain-list reasons">
              {s.reasons.map((r, i) => (
                <li key={i}>
                  <span className={`src src-${r.source}`}>{sourceLabel[r.source]}</span>
                  <span>{r.text}</span>
                  <Evidence r={r} />
                </li>
              ))}
            </ul>
            <p className="muted small">
              Kernel facts decide. The agent's own log and the model can raise a tier, never lower it. A tier never
              freezes anything by itself.
            </p>
          </div>

          <div className="row2">
            <div className="card">
              <h3>Kernel, last {k?.window_min ?? 10} min</h3>
              <Facts rows={[
                ["Actions seen", k?.events], ["Failed", k?.failed], ["Refused by permissions", k?.refused],
                ["Never touched before", k?.baseline_events && k.baseline_events >= 20 ? k?.new_resources : "no baseline yet"],
                ["New destinations", k?.new_destinations], ["Writes outside profile", k?.shared_writes],
              ]} />
            </div>
            <div className="card">
              <h3>Agent's own log, last {k?.window_min ?? 10} min</h3>
              <Facts rows={[
                ["Entries", a?.entries], ["Text aimed at the monitor", a?.injection_markers],
                ["Mentions of getting around a limit", a?.workaround_markers], ["Longest error streak", a?.retry_streak],
                ["Actions missing from the log", a?.unlogged],
                ["Model", s.model.name ? `${s.model.name}: ${s.model.answer ?? "–"}` : "off"],
              ]} />
            </div>
          </div>
        </>
      )}

      {canEditGate && <GatePanel token={token} workload={workload} onError={onError} />}

      <div className="card">
        <h3>Agent's own log <span className="tag untrusted">untrusted</span></h3>
        {log.length === 0 ? (
          <p className="muted">
            No agent log received. Ship tool calls and reasoning to <code>POST /api/v1/agents/{workload.id}/log</code> from a
            tool gateway or LLM proxy the agent cannot write to.
          </p>
        ) : (
          <ul className="agent-log">
            {log.map((e) => (
              <li key={e.id}>
                <span className="mono muted">{clock(e.ts)}</span>
                <span className={`pill kind-${e.kind}`}>{e.kind.replace("_", " ")}</span>
                {e.tool && <code>{e.tool}</code>}
                {e.status && <span className={`pill status-${e.status}`}>{e.status}</span>}
                <span className="log-text">{e.text || e.target}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

const HOLD_AT: { id: HoldAt; label: string; help: string }[] = [
  { id: "never", label: "Never", help: "No gate. Risky tools run without a human." },
  { id: "rising", label: "From Rising", help: "Hold risky tools as soon as the pattern starts moving away from the task." },
  { id: "high", label: "From High", help: "Hold risky tools only once there are strong signs of working around limits." },
];

const DEFAULT_GATE: GateConfig = { risky_tools: [], hold_at: "never", ttl_s: 600 };

function parseTools(text: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of text.split(/[\n,]/)) {
    const t = raw.trim();
    if (t && !seen.has(t)) {
      seen.add(t);
      out.push(t);
    }
  }
  return out;
}

/**
 * Approval gate (CONTRACTS §3.1): which tools the gateway must hold for a human once this
 * workload's tier reaches hold_at. Stored by the API per workload, outside the engine profile.
 */
function GatePanel({ token, workload, onError }: { token: string; workload: Workload; onError: (e: unknown) => void }) {
  const [saved, setSaved] = useState<GateConfig | null>(null);
  const [tools, setTools] = useState("");
  const [holdAt, setHoldAt] = useState<HoldAt>("never");
  const [ttl, setTtl] = useState("600");
  const [status, setStatus] = useState<"loading" | "ready" | "unavailable">("loading");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);

  const apply = (g: GateConfig) => {
    setSaved(g);
    setTools((g.risky_tools ?? []).join("\n"));
    setHoldAt(g.hold_at ?? "never");
    setTtl(String(g.ttl_s ?? 600));
  };

  useEffect(() => {
    let alive = true;
    optional(api.gate(token, workload.id))
      .then((g) => {
        if (!alive) return;
        // 404 = no gate configured yet (or an API without the endpoint): start from the default.
        apply(g && Array.isArray(g.risky_tools) ? g : DEFAULT_GATE);
        setStatus("ready");
      })
      .catch((e) => {
        if (!alive) return;
        setStatus("unavailable");
        onError(e);
      });
    return () => {
      alive = false;
    };
  }, [token, workload.id, onError]);

  const draft: GateConfig = { risky_tools: parseTools(tools), hold_at: holdAt, ttl_s: Number(ttl) };
  const ttlOk = Number.isInteger(draft.ttl_s) && draft.ttl_s >= 30 && draft.ttl_s <= 86_400;
  const toolsOk = draft.risky_tools.length <= 64 && draft.risky_tools.every((t) => t.length <= 64);
  // Field-wise: the API may echo extra keys (workload id, timestamps) that are not part of the gate.
  const dirty = !saved || draft.hold_at !== (saved.hold_at ?? "never") || draft.ttl_s !== (saved.ttl_s ?? 600)
    || draft.risky_tools.join("\n") !== (saved.risky_tools ?? []).join("\n");
  const active = draft.hold_at !== "never" && draft.risky_tools.length > 0;

  async function save() {
    setBusy(true);
    setNote(null);
    setProblem(null);
    try {
      const g = await api.saveGate(token, workload.id, draft);
      apply(g && Array.isArray(g.risky_tools) ? g : draft);
      setNote(active ? "Saved. The gateway holds these tools from the next check." : "Saved. No gate: risky tools run without a hold.");
    } catch (e) {
      if (e instanceof ApiError && (e.status === 422 || e.status === 400)) {
        setProblem(e.fields.length ? e.fields.map((f) => `${f.field}: ${f.message}`).join("; ") : e.message);
      } else onError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card gate" aria-label={`Approval gate for ${workload.name}`}>
      <h3>Approval gate</h3>
      <p className="muted small">
        When this workload's early-warning tier reaches the level below, the gateway holds the listed tools until an
        operator approves them under Approvals. A hold never pauses the container.
      </p>
      {status === "loading" && <p className="muted">Loading…</p>}
      {status === "unavailable" && <p className="muted small">The gate could not be loaded from the API.</p>}
      {status === "ready" && (
        <fieldset disabled={busy}>
          <div>
            <label htmlFor="gate-tools">Risky tools, one per line</label>
            <textarea id="gate-tools" className="mono" rows={4} value={tools} spellCheck={false}
              placeholder={"shell\nkubectl\nterraform *"} onChange={(e) => { setTools(e.target.value); setNote(null); }} />
            <p className="muted small">Exact tool names as the gateway reports them; <code>*</code> matches any run of characters. Up to 64.</p>
            {draft.risky_tools.length > 0 && (
              <div className="pills chips" aria-label="Risky tools">
                {draft.risky_tools.map((t) => <code key={t}>{t}</code>)}
              </div>
            )}
          </div>
          <div className="row2">
            <div>
              <label htmlFor="gate-hold">Hold at</label>
              <select id="gate-hold" value={holdAt} onChange={(e) => { setHoldAt(e.target.value as HoldAt); setNote(null); }}>
                {HOLD_AT.map((h) => <option key={h.id} value={h.id}>{h.label}</option>)}
              </select>
              <p className="muted small">{HOLD_AT.find((h) => h.id === holdAt)?.help}</p>
            </div>
            <div>
              <label htmlFor="gate-ttl">Hold expires after (seconds)</label>
              <input id="gate-ttl" type="number" inputMode="numeric" min={30} max={86400} step={1} value={ttl}
                onChange={(e) => { setTtl(e.target.value); setNote(null); }} />
              <p className="muted small">An undecided hold reads as denied after this long.</p>
            </div>
          </div>
          {!toolsOk && <p className="form-error small">At most 64 tools, each at most 64 characters.</p>}
          {!ttlOk && <p className="form-error small">Enter a whole number of seconds between 30 and 86400.</p>}
          {problem && <p className="form-error small">{problem}</p>}
          <div className="action-buttons">
            <button type="button" className="btn primary" disabled={busy || !dirty || !ttlOk || !toolsOk} onClick={save}>
              {busy ? "Saving…" : "Save gate"}
            </button>
            {dirty && saved && <button type="button" className="btn quiet" onClick={() => apply(saved)}>Discard</button>}
          </div>
          {note && <p className="note" role="status">{note}</p>}
          {!dirty && !note && (
            <p className="muted small">{active ? `Holding ${draft.risky_tools.length} tool${draft.risky_tools.length === 1 ? "" : "s"} from tier ${HOLD_AT.find((h) => h.id === holdAt)?.label.replace("From ", "").toLowerCase()}.` : "No gate configured."}</p>
          )}
        </fieldset>
      )}
    </div>
  );
}

function Facts({ rows }: { rows: [string, unknown][] }) {
  return (
    <dl className="facts">
      {rows.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v === undefined || v === null ? "–" : String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

function Evidence({ r }: { r: DriftReason }) {
  const ev = r.evidence || {};
  const sample = (ev.sample as unknown[] | undefined) ?? (ev.entries as { id: string; match: string }[] | undefined)?.map((e) => `"${e.match}"`);
  if (!sample || sample.length === 0) return null;
  return <span className="evidence mono">{sample.slice(0, 4).map(String).join(", ")}</span>;
}

/** Step chart of tier changes over time; a tier holds until the next change. */
function TrendLine({ points }: { points: { tier: Tier; at: string }[] }) {
  const rank: Record<Tier, number> = { steady: 0, rising: 1, high: 2, crossed: 3 };
  const W = 420, H = 84, pad = 6, top = 16;
  const t0 = parseTime(points[0].at);
  const t1 = Math.max(Date.now(), parseTime(points[points.length - 1].at));
  const span = Math.max(t1 - t0, 60_000);
  const x = (iso: string) => pad + ((parseTime(iso) - t0) / span) * (W - 2 * pad);
  const y = (t: Tier) => H - pad - (rank[t] / 3) * (H - pad - top);
  let d = "";
  points.forEach((p, i) => {
    const px = x(p.at), py = y(p.tier);
    if (i === 0) d += `M${px},${py}`;
    else d += ` H${px} V${py}`;
  });
  d += ` H${W - pad}`;
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Tier over time">
        {(["steady", "rising", "high", "crossed"] as Tier[]).map((t) => (
          <g key={t}>
            <line x1={pad} x2={W - pad} y1={y(t)} y2={y(t)} className="grid" />
            <text x={W - pad} y={y(t) - 2} className="axis" textAnchor="end">{tierLabel[t]}</text>
          </g>
        ))}
        <path d={d} className="line" />
        {points.map((p, i) => <circle key={i} cx={x(p.at)} cy={y(p.tier)} r={3} className={`dot tier-${p.tier}`} />)}
      </svg>
      <figcaption className="muted small">
        {points.length} change{points.length === 1 ? "" : "s"} since {new Date(t0).toLocaleString()}
      </figcaption>
    </figure>
  );
}
