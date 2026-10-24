import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "./api";
import { ErrorBoundary } from "./ErrorBoundary";
import { ago, parseTime } from "./format";
import type {
  ControllerSync, ExecClass, FieldError, PolicyDetail, PolicyList, PolicyVersion, ProfileBody, ResponseAction,
} from "./types";

const NEW = "\u0000new";

const CLASSES: { id: ExecClass; label: string; examples: string }[] = [
  { id: "INTERPRETER", label: "Interpreters & shells", examples: "python, node, perl, sh, bash" },
  { id: "DIAGNOSTIC", label: "Diagnostic tools", examples: "ls, cat, ps, grep, ip, netstat" },
  { id: "NET_CLIENT", label: "Network clients", examples: "curl, wget, ssh, nc, scp, openssl" },
  { id: "PRIVILEGED_TOOL", label: "Privileged tools", examples: "sudo, mount, nsenter, chroot" },
  { id: "OTHER", label: "Everything else", examples: "the workload's own binary, unrecognised programs" },
];

const RESPONSES: { id: ResponseAction; label: string; help: string }[] = [
  { id: "ALERT", label: "Alert only", help: "Open an incident; nothing is stopped." },
  { id: "PAUSE_CONTAINER", label: "Pause the container", help: "Freeze a dedicated worker until an operator resumes or terminates it." },
  { id: "REVOKE_SESSION", label: "Revoke the session", help: "End the offending session of a shared service (needs a session adapter)." },
];

function blank(): ProfileBody {
  return {
    name: "", kind: "ai_worker", description: "", mode: "SHADOW_MODE",
    decoys: [], protected_read: ["/root/**", "/etc/shadow"], read_allowed: [], write_allowed: [],
    exec_allowed_classes: [], exec_denied_classes: ["NET_CLIENT", "PRIVILEGED_TOOL"], egress_allowed: [],
    egress_allowed_domains: [],
    response: { on_violation: "ALERT", on_structural_guard: "ALERT" },
  };
}

const LIST_FIELDS = ["decoys", "protected_read", "write_allowed", "exec_allowed_classes", "exec_denied_classes", "egress_allowed"] as const;

/**
 * Minimal shape guard for JSON pasted into the editor. Valid JSON that is not a profile
 * (`{}`, `null`, a list, a profile with `decoys: "x"`) must never become the draft: the form
 * indexes these fields directly and would throw while rendering. Only presence and type are
 * checked here; the API validator judges the values.
 */
export function asProfile(v: unknown): { ok: true; body: ProfileBody } | { ok: false; missing: string } {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return { ok: false, missing: "object" };
  const o = v as Record<string, unknown>;
  if (typeof o.name !== "string") return { ok: false, missing: "name" };
  if (o.kind !== "ai_worker" && o.kind !== "shared_service") return { ok: false, missing: "kind (ai_worker or shared_service)" };
  if (typeof o.response !== "object" || o.response === null || Array.isArray(o.response)) return { ok: false, missing: "response" };
  for (const f of LIST_FIELDS) {
    if (!Array.isArray(o[f])) return { ok: false, missing: f };
  }
  if (o.read_allowed !== null && o.read_allowed !== undefined && !Array.isArray(o.read_allowed)) {
    return { ok: false, missing: "read_allowed (list or null)" };
  }
  if (o.egress_allowed_domains !== undefined && !Array.isArray(o.egress_allowed_domains)) {
    return { ok: false, missing: "egress_allowed_domains (list)" };
  }
  const r = o.response as Record<string, unknown>;
  const body = {
    ...o,
    description: typeof o.description === "string" ? o.description : "",
    mode: o.mode === "ACTIVE_FREEZE_MODE" ? "ACTIVE_FREEZE_MODE" : "SHADOW_MODE",
    read_allowed: o.read_allowed === undefined ? null : o.read_allowed,
    response: {
      ...r,
      on_violation: typeof r.on_violation === "string" ? r.on_violation : "ALERT",
      on_structural_guard: typeof r.on_structural_guard === "string" ? r.on_structural_guard : "ALERT",
    },
  } as unknown as ProfileBody;
  return { ok: true, body };
}

/** Entries the operator typed for egress_allowed_domains: trimmed and lowercased, never undefined. */
function domainsOf(b: ProfileBody): string[] {
  return Array.isArray(b.egress_allowed_domains) ? b.egress_allowed_domains : [];
}

/**
 * Comparable form: `version` is assigned by the API, so it never makes a draft dirty; an absent
 * egress_allowed_domains (profiles saved before the field existed) equals an empty one.
 */
function canon(b: ProfileBody): string {
  const { version: _v, ...rest } = b;
  return JSON.stringify({ ...rest, egress_allowed_domains: domainsOf(b) });
}

function short(rev: string) {
  return rev ? rev.slice(0, 8) : "local files";
}

export function Policies({ token, canEdit, tick, onError }: {
  token: string;
  canEdit: boolean;
  /** bumped by the live stream; reloads the list */
  tick: number;
  onError: (e: unknown) => void;
}) {
  const [list, setList] = useState<PolicyList | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [seed, setSeed] = useState<ProfileBody | null>(null);

  async function load() {
    try {
      const l = await api.policies(token);
      setList(l);
      setSelected((s) => s ?? l.profiles[0]?.name ?? null);
    } catch (e) {
      onError(e);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, tick]);

  function startNew(from?: ProfileBody) {
    setSeed(from ? { ...from, name: `${from.name}-copy`, version: null } : blank());
    setSelected(NEW);
  }

  return (
    <div className="split">
      <aside className="list-pane" aria-label="Policies">
        <div className="pane-head">
          <h3>Policies</h3>
          {canEdit && <button className="btn primary" onClick={() => startNew()}>New policy</button>}
        </div>
        {list && <SyncStatus list={list} />}
        {!list ? <p className="muted pad">Loading…</p> : list.profiles.length === 0 && selected !== NEW ? (
          <div className="empty">
            <p className="empty-title">No policies yet</p>
            <p className="muted">A policy says what a workload may do and what River3 does when it does something else.</p>
          </div>
        ) : (
          <ul className="incident-list">
            {selected === NEW && (
              <li><button className="incident-row selected"><span className="row-title">New policy</span>
                <span className="row-meta">Not saved yet</span></button></li>
            )}
            {list.profiles.map((p) => (
              <li key={p.name}>
                <button className={`incident-row${selected === p.name ? " selected" : ""}`} onClick={() => setSelected(p.name)}>
                  <span className="row-top">
                    <span>{p.kind === "ai_worker" ? "AI worker" : "Shared service"}</span>
                    <span className="row-time">v{p.version} · {ago(p.updated_at)}</span>
                  </span>
                  <span className="row-title mono">{p.name}</span>
                  <span className="row-status">
                    {p.body.mode === "ACTIVE_FREEZE_MODE"
                      ? <span className="sev-pill sev-critical">Active</span>
                      : <span className="tag">Shadow</span>}
                    <span>{responseLabel(p.body.response.on_violation)}</span>
                    <span>· {p.workloads ?? 0} workload{p.workloads === 1 ? "" : "s"}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </aside>
      {selected === null ? (
        <section className="detail-pane empty">
          <p className="empty-title">Select a policy</p>
          <p className="muted">Or create one to describe what a workload is allowed to do.</p>
        </section>
      ) : (
        <ErrorBoundary label="Editor" resetKey={selected === NEW ? `new-${seed?.name}` : selected}>
        <PolicyEditor
          key={selected === NEW ? `new-${seed?.name}` : selected}
          token={token}
          name={selected === NEW ? null : selected}
          seed={selected === NEW ? seed ?? blank() : null}
          canEdit={canEdit}
          tick={tick}
          onSaved={(name) => {
            setSelected(name);
            load();
          }}
          onDeleted={() => {
            setSelected(null);
            load();
          }}
          onCopy={startNew}
          onCancelNew={() => setSelected(list?.profiles[0]?.name ?? null)}
          onError={onError}
        />
        </ErrorBoundary>
      )}
    </div>
  );
}

function SyncStatus({ list }: { list: PolicyList }) {
  if (list.controllers.length === 0) {
    return (
      <div className="sync warn">
        <strong>No controller is using these policies.</strong>
        <span className="muted small">Start <code>river3-containd</code> with <code>-profiles-from-api</code> to enforce them.</span>
      </div>
    );
  }
  return (
    <div className="sync-list">
      {list.controllers.map((c) => <ControllerLine key={c.controller} c={c} />)}
      {list.unbound.length > 0 && (
        <div className="sync bad">
          <span>
            Workloads are assigned to {list.unbound.map((n, i) => <span key={n}>{i > 0 && ", "}<code>{n}</code></span>)}, which no
            policy here defines. A controller with such a workload enrolled keeps its previous policies until they exist.
          </span>
        </div>
      )}
    </div>
  );
}

function ControllerLine({ c }: { c: ControllerSync }) {
  const stale = Date.now() - parseTime(c.reported_at) > 3 * 60_000;
  const tone = c.error ? "bad" : !c.current || stale ? "warn" : "ok";
  return (
    <div className={`sync ${tone}`} title={c.error || undefined}>
      <span><strong className="mono">{c.controller}</strong>{" "}
        {c.error ? "refused the latest change" : c.current ? "is enforcing the latest policies" : "hasn't picked up the latest change yet"}
      </span>
      <span className="muted small">
        enforcing {short(c.active_revision)} · {c.profiles} profile{c.profiles === 1 ? "" : "s"} · heard {ago(c.reported_at)}
        {stale && " (silent)"}
      </span>
      {c.error && <span className="small sync-error">{c.error}</span>}
    </div>
  );
}

function responseLabel(a: ResponseAction) {
  return RESPONSES.find((r) => r.id === a)?.label ?? a;
}

type Tab = "rules" | "json" | "history";

function PolicyEditor({ token, name, seed, canEdit, tick, onSaved, onDeleted, onCopy, onCancelNew, onError }: {
  token: string;
  name: string | null;
  seed: ProfileBody | null;
  canEdit: boolean;
  tick: number;
  onSaved: (name: string) => void;
  onDeleted: () => void;
  onCopy: (from: ProfileBody) => void;
  onCancelNew: () => void;
  onError: (e: unknown) => void;
}) {
  const isNew = name === null;
  const [detail, setDetail] = useState<PolicyDetail | null>(null);
  const [draft, setDraft] = useState<ProfileBody | null>(seed);
  const [tab, setTab] = useState<Tab>("rules");
  const [errors, setErrors] = useState<FieldError[]>([]);
  const [comment, setComment] = useState("");
  const [ackActive, setAckActive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [conflict, setConflict] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);

  async function load(resetDraft: boolean) {
    if (!name) return;
    try {
      const d = await api.policy(token, name);
      setDetail(d);
      if (resetDraft && d.profile) setDraft(d.profile.body);
    } catch (e) {
      onError(e);
    }
  }

  useEffect(() => {
    load(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [name, token]);

  // Someone else saved while this was open: keep the draft, but say so.
  const base = detail?.profile ?? null;
  useEffect(() => {
    if (!name || !base) return;
    api.policy(token, name).then((d) => {
      if (d.profile && d.profile.version !== base.version) {
        setConflict(`${d.profile.updated_by} saved version ${d.profile.version} while you were editing.`);
      }
    }).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  const dirty = !!draft && (isNew || !base || canon(draft) !== canon(base.body));

  // Validate as you type, with the same rules the API and the policy engine apply.
  useEffect(() => {
    if (!draft || !canEdit || !dirty) {
      setErrors([]);
      return;
    }
    const t = setTimeout(() => {
      api.validatePolicy(token, draft).then((r) => setErrors(r.errors)).catch(() => undefined);
    }, 350);
    return () => clearTimeout(t);
  }, [draft, token, canEdit, dirty]);

  if (!draft) return <section className="detail-pane"><p className="muted">Loading…</p></section>;

  const readOnly = !canEdit;
  const goingActive = draft.mode === "ACTIVE_FREEZE_MODE" && base?.body.mode !== "ACTIVE_FREEZE_MODE";
  const canSave = dirty && errors.length === 0 && comment.trim().length >= 8 && (!goingActive || ackActive) && !busy
    && draft.name.trim() !== "";

  function set<K extends keyof ProfileBody>(k: K, v: ProfileBody[K]) {
    setDraft((d) => (d ? { ...d, [k]: v } : d));
    setNote(null);
  }

  async function save() {
    if (!draft) return;
    setBusy(true);
    setNote(null);
    try {
      const saved = await api.savePolicy(token, draft, base?.version ?? 0, comment.trim());
      setComment("");
      setAckActive(false);
      setConflict(null);
      setNote(`Saved version ${saved.version}. Controllers using the console's policies pick it up within seconds.`);
      if (isNew) onSaved(saved.name);
      else {
        await load(true);
        onSaved(saved.name);
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 422 && e.fields.length) setErrors(e.fields);
      else if (e instanceof ApiError && e.status === 409) setConflict(e.message);
      else onError(e);
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!base) return;
    setBusy(true);
    try {
      await api.deletePolicy(token, base.name, base.version, comment.trim());
      onDeleted();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) setConflict(e.message);
      else onError(e);
    } finally {
      setBusy(false);
    }
  }

  const errs = (prefix: string) => errors.filter((e) => e.field === prefix || e.field.startsWith(`${prefix}.`));
  const workloads = detail?.workloads ?? [];

  return (
    <section className="detail-pane" aria-label="Policy editor">
      <header className="detail-head">
        <div className="pills">
          {draft.mode === "ACTIVE_FREEZE_MODE" ? <span className="sev-pill sev-critical">Active</span> : <span className="tag">Shadow</span>}
          {base && <span className="pill">Version {base.version}</span>}
          {dirty && !isNew && <span className="sev-pill sev-high">Unsaved changes</span>}
          {isNew && <span className="sev-pill sev-info">New</span>}
        </div>
        {isNew ? (
          <>
            <label htmlFor="pname">Name</label>
            <input id="pname" className="mono" value={draft.name} placeholder="e.g. invoice-agent"
              onChange={(e) => set("name", e.target.value.trim())} autoFocus />
            <FieldErrors list={errs("name")} />
          </>
        ) : (
          <h2 className="mono">{draft.name}</h2>
        )}
        {base && (
          <p className="muted">
            Last changed by {base.updated_by} {ago(base.updated_at)} ·{" "}
            {workloads.length === 0 ? "no workloads assigned" : <>assigned to {workloads.map((w) => w.name).join(", ")}</>}
          </p>
        )}
      </header>

      {conflict && (
        <div className="banner error" role="alert">
          {conflict}
          <button className="btn quiet" onClick={() => { setConflict(null); load(true); }}>Discard my changes and reload</button>
        </div>
      )}

      <div className="segmented tabs" role="tablist">
        {(["rules", "json", "history"] as Tab[]).map((t) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)} disabled={t === "history" && isNew}>
            {t === "rules" ? "Rules" : t === "json" ? "JSON" : `History${detail ? ` (${detail.history.length})` : ""}`}
          </button>
        ))}
      </div>

      {tab === "rules" && (
        <div className="policy-grid">
          <div className="policy-form">
            <fieldset disabled={readOnly}>
              <section className="card">
                <h3>Workload</h3>
                <div className="row2">
                  <div>
                    <label htmlFor="kind">Kind</label>
                    <select id="kind" value={draft.kind} onChange={(e) => {
                      const kind = e.target.value as ProfileBody["kind"];
                      const fix = (a: ResponseAction): ResponseAction => (kind === "shared_service" && a === "PAUSE_CONTAINER" ? "ALERT" : a);
                      setDraft({ ...draft, kind, response: { on_violation: fix(draft.response.on_violation), on_structural_guard: fix(draft.response.on_structural_guard) } });
                    }}>
                      <option value="ai_worker">AI worker (dedicated container)</option>
                      <option value="shared_service">Shared service (serves many users)</option>
                    </select>
                  </div>
                </div>
                <label htmlFor="desc">Description</label>
                <textarea id="desc" rows={2} value={draft.description} maxLength={2048}
                  placeholder="What this workload does, in a sentence" onChange={(e) => set("description", e.target.value)} />
              </section>

              <section className="card">
                <h3>When it steps outside these rules</h3>
                <div className="choice-row" role="radiogroup" aria-label="Mode">
                  <Choice checked={draft.mode === "SHADOW_MODE"} onChange={() => set("mode", "SHADOW_MODE")}
                    title="Shadow" help="Record violations as incidents. Never stop anything. Start here." />
                  <Choice checked={draft.mode === "ACTIVE_FREEZE_MODE"} onChange={() => set("mode", "ACTIVE_FREEZE_MODE")}
                    title="Active" help="Carry out the response below automatically, when the evidence is verified." tone="bad" />
                </div>
                <label htmlFor="onv">Response to a violation</label>
                <select id="onv" value={draft.response.on_violation}
                  onChange={(e) => set("response", { ...draft.response, on_violation: e.target.value as ResponseAction })}>
                  {RESPONSES.map((r) => (
                    <option key={r.id} value={r.id} disabled={draft.kind === "shared_service" && r.id === "PAUSE_CONTAINER"}>{r.label}</option>
                  ))}
                </select>
                <p className="muted small">{RESPONSES.find((r) => r.id === draft.response.on_violation)?.help}
                  {draft.mode === "SHADOW_MODE" && draft.response.on_violation !== "ALERT" && " In shadow mode this is only recorded as what would have happened."}</p>
                <label htmlFor="ong">Response when the model guard (Laya) flags the event's facts</label>
                <select id="ong" value={draft.response.on_structural_guard}
                  onChange={(e) => set("response", { ...draft.response, on_structural_guard: e.target.value as ResponseAction })}>
                  {RESPONSES.map((r) => (
                    <option key={r.id} value={r.id} disabled={draft.kind === "shared_service" && r.id === "PAUSE_CONTAINER"}>{r.label}</option>
                  ))}
                </select>
                <p className="muted small">Advisory. The guard can never contain on the event's payload alone.</p>
                <FieldErrors list={[...errs("response"), ...errs("mode"), ...errors.filter((e) => e.field === "")]} />
              </section>

              <section className="card">
                <h3>Files</h3>
                <PathList label="Decoys" help="Planted fake secrets. Any open is a violation, even if another rule allows the path."
                  values={draft.decoys} onChange={(v) => set("decoys", v)} errors={errs("decoys")} placeholder="/opt/config/.db_recovery_creds" />
                <PathList label="Never read" help="Real secrets this workload must never open for reading."
                  values={draft.protected_read} onChange={(v) => set("protected_read", v)} errors={errs("protected_read")} placeholder="/root/.aws/**" />
                <div className="field-head">
                  <span className="field-label">May read</span>
                  <label className="inline">
                    <input type="checkbox" checked={draft.read_allowed !== null}
                      onChange={(e) => set("read_allowed", e.target.checked ? [] : null)} />
                    Only the paths listed
                  </label>
                </div>
                {draft.read_allowed === null ? (
                  <p className="muted small">Reads are not restricted, apart from decoys and the paths above.</p>
                ) : (
                  <PathList help="Every other read is out of scope." values={draft.read_allowed}
                    onChange={(v) => set("read_allowed", v)} errors={errs("read_allowed")} placeholder="/data/**" />
                )}
                <PathList label="May write" help="Every other write is out of scope. Leave empty for no writes at all."
                  values={draft.write_allowed} onChange={(v) => set("write_allowed", v)} errors={errs("write_allowed")} placeholder="/out/**" />
                <p className="muted small">
                  Patterns: <code>*</code> and <code>?</code> match within one folder; a trailing <code>/**</code> covers the whole tree
                  (<code>/app/**</code> matches <code>/app/x/y</code>, not <code>/application</code>).
                </p>
              </section>

              <section className="card">
                <h3>Programs it may start</h3>
                <table className="classes">
                  <tbody>
                    {CLASSES.map((c) => {
                      const state = draft.exec_denied_classes.includes(c.id) ? "deny"
                        : draft.exec_allowed_classes.includes(c.id) ? "allow" : "none";
                      const setState = (s: "allow" | "deny" | "none") => {
                        const allow = draft.exec_allowed_classes.filter((x) => x !== c.id);
                        const deny = draft.exec_denied_classes.filter((x) => x !== c.id);
                        if (s === "allow") allow.push(c.id);
                        if (s === "deny") deny.push(c.id);
                        setDraft({ ...draft, exec_allowed_classes: allow, exec_denied_classes: deny });
                      };
                      return (
                        <tr key={c.id}>
                          <td>
                            <div>{c.label}</div>
                            <div className="muted small">{c.examples}</div>
                          </td>
                          <td className="tri">
                            <div className="segmented mini" role="radiogroup" aria-label={c.label}>
                              {(["allow", "none", "deny"] as const).map((s) => (
                                <button key={s} type="button" role="radio" aria-checked={state === s} aria-selected={state === s}
                                  className={`tri-${s}`} onClick={() => setState(s)}>
                                  {s === "allow" ? "Allow" : s === "deny" ? "Deny" : "Not listed"}
                                </button>
                              ))}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
                <p className="muted small">Only allowed classes are in scope. Deny makes the rule explicit in incidents and wins over allow.</p>
                <FieldErrors list={[...errs("exec_allowed_classes"), ...errs("exec_denied_classes")]} />
              </section>

              <section className="card">
                <h3>Network</h3>
                <PathList label="May connect to" help="IP ranges in CIDR form. Leave both lists empty for no outbound connections at all (loopback included)."
                  values={draft.egress_allowed} onChange={(v) => set("egress_allowed", v)} errors={errs("egress_allowed")}
                  placeholder="10.0.0.0/8" mono />
                <PathList label="Allowed domains"
                  help="Hostnames, lowercase; a leading *. covers subdomains (resolved for the apex only). No ports, schemes or paths."
                  values={domainsOf(draft)} errors={errs("egress_allowed_domains")} placeholder="api.example.com" mono
                  normalize={(v) => v.trim().toLowerCase()}
                  onChange={(v) => set("egress_allowed_domains", v)} />
                <p className="muted small caveat">
                  Resolved by the controller every 60 s. A CDN can rotate faster than that; for strict control use an egress proxy.
                  The engine itself matches IP addresses only.
                </p>
              </section>
            </fieldset>
          </div>
          <aside className="card plain">
            <h3>In plain words</h3>
            <PlainSummary p={draft} />
          </aside>
        </div>
      )}

      {tab === "json" && <JsonTab draft={draft} readOnly={readOnly} errors={errors} onChange={(b) => setDraft(b)} />}

      {tab === "history" && detail && (
        <HistoryTab history={detail.history} current={base?.version ?? null} canEdit={canEdit}
          onLoad={(b) => { setDraft({ ...b, name: draft.name }); setTab("rules"); setNote("Loaded an earlier version into the editor. Review it, then save to make it current."); }} />
      )}

      {canEdit && (
        <footer className="save-bar">
          {goingActive && (
            <label className="inline warn-text">
              <input type="checkbox" checked={ackActive} onChange={(e) => setAckActive(e.target.checked)} />
              I understand that in active mode River3 will {draft.response.on_violation === "PAUSE_CONTAINER" ? "pause containers" : draft.response.on_violation === "REVOKE_SESSION" ? "revoke sessions" : "act"} on its own when this policy is violated.
            </label>
          )}
          <label htmlFor="comment">{deleting ? "Why are you deleting it?" : "What changed and why?"}</label>
          <textarea id="comment" rows={2} value={comment} onChange={(e) => setComment(e.target.value)}
            placeholder={deleting ? "e.g. workload retired" : "e.g. allow writes to /out for the nightly export"} />
          <div className="action-buttons">
            {deleting ? (
              <>
                <button className="btn danger" disabled={busy || comment.trim().length < 8} onClick={remove}>
                  {busy ? "Deleting…" : "Delete policy"}
                </button>
                <button className="btn quiet" onClick={() => setDeleting(false)}>Cancel</button>
              </>
            ) : (
              <>
                <button className="btn primary" disabled={!canSave} onClick={save}>
                  {busy ? "Saving…" : isNew ? "Create policy" : `Save as version ${(base?.version ?? 0) + 1}`}
                </button>
                {dirty && !isNew && <button className="btn quiet" onClick={() => base && setDraft(base.body)}>Discard changes</button>}
                {isNew && <button className="btn quiet" onClick={onCancelNew}>Cancel</button>}
                {!isNew && !dirty && <button className="btn quiet" onClick={() => onCopy(draft)}>Copy as new policy</button>}
                {!isNew && !dirty && (
                  <button className="btn quiet" disabled={workloads.length > 0} onClick={() => setDeleting(true)}
                    title={workloads.length ? "Assigned to workloads; reassign them first" : ""}>Delete…</button>
                )}
              </>
            )}
          </div>
          <p className="muted small">
            {errors.length > 0 ? <span className="form-error">Fix {errors.length} problem{errors.length === 1 ? "" : "s"} before saving.</span>
              : dirty && comment.trim().length < 8 ? "A short reason (8+ characters) is required; it goes in the history and the audit log."
              : !dirty && !deleting ? "No changes." : ""}
          </p>
          {note && <p className="note" role="status">{note}</p>}
        </footer>
      )}
      {!canEdit && <p className="muted small">Your role can view policies but not change them.</p>}
    </section>
  );
}

function Choice({ checked, onChange, title, help, tone }: {
  checked: boolean; onChange: () => void; title: string; help: string; tone?: "bad";
}) {
  return (
    <label className={`choice${checked ? " on" : ""}${tone ? ` ${tone}` : ""}`}>
      <input type="radio" checked={checked} onChange={onChange} />
      <span><strong>{title}</strong><span className="muted small">{help}</span></span>
    </label>
  );
}

function FieldErrors({ list }: { list: FieldError[] }) {
  if (list.length === 0) return null;
  return (
    <ul className="field-errors">
      {list.map((e, i) => <li key={i}>{e.message}</li>)}
    </ul>
  );
}

function PathList({ label, help, values, onChange, errors, placeholder, mono = true, normalize }: {
  label?: string; help: string; values: string[]; onChange: (v: string[]) => void; errors: FieldError[];
  placeholder: string; mono?: boolean;
  /** applied to an entry when it is added or edited (e.g. lowercase a hostname) */
  normalize?: (v: string) => string;
}) {
  const [adding, setAdding] = useState("");
  const rowError = (i: number) => errors.filter((e) => e.field.split(".")[1] === String(i));
  const fix = normalize ?? ((v: string) => v);
  function add() {
    const v = fix(adding.trim());
    if (!v) return;
    onChange([...values, v]);
    setAdding("");
  }
  return (
    <div className="path-list">
      {label && <span className="field-label">{label}</span>}
      <span className="muted small">{help}</span>
      <ul>
        {values.map((v, i) => (
          <li key={i} className={rowError(i).length ? "has-error" : ""}>
            <input className={mono ? "mono" : ""} value={v} aria-label={`${label ?? "entry"} ${i + 1}`}
              onChange={(e) => onChange(values.map((x, j) => (j === i ? fix(e.target.value) : x)))} />
            <button type="button" className="btn quiet" aria-label="Remove" onClick={() => onChange(values.filter((_, j) => j !== i))}>Remove</button>
            {rowError(i).map((e, k) => <span key={k} className="form-error small">{e.message}</span>)}
          </li>
        ))}
        <li>
          <input className={mono ? "mono" : ""} value={adding} placeholder={placeholder} aria-label={`Add to ${label ?? "list"}`}
            onChange={(e) => setAdding(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); add(); } }} />
          <button type="button" className="btn" onClick={add} disabled={!adding.trim()}>Add</button>
        </li>
      </ul>
      <FieldErrors list={errors.filter((e) => e.field.split(".").length === 1)} />
    </div>
  );
}

function JsonTab({ draft, readOnly, errors, onChange }: {
  draft: ProfileBody; readOnly: boolean; errors: FieldError[]; onChange: (b: ProfileBody) => void;
}) {
  const pretty = useMemo(() => JSON.stringify(draft, null, 2), [draft]);
  const [text, setText] = useState(pretty);
  const [parseError, setParseError] = useState<string | null>(null);
  const [shapeError, setShapeError] = useState<string | null>(null);
  useEffect(() => {
    // Follow outside changes (form, reload) unless the text here is mid-edit and not yet a profile.
    if (!parseError && !shapeError) setText(pretty);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pretty]);
  return (
    <div className="json-tab">
      <p className="muted small">The exact profile the policy engine loads. Paste one from a file to import it. <code>version</code> is set by the console when you save.</p>
      <textarea className="mono json" rows={24} spellCheck={false} value={text} readOnly={readOnly}
        aria-invalid={!!(parseError || shapeError)} aria-describedby="json-status"
        onChange={(e) => {
          setText(e.target.value);
          let v: unknown;
          try {
            v = JSON.parse(e.target.value);
          } catch (err) {
            setParseError(err instanceof Error ? err.message : String(err));
            return;
          }
          setParseError(null);
          // Valid JSON that is not a profile keeps the previous draft; only a real profile replaces it.
          const shaped = asProfile(v);
          if (!shaped.ok) {
            setShapeError(`Not a profile: missing ${shaped.missing}`);
            return;
          }
          setShapeError(null);
          onChange(shaped.body);
        }} />
      <div id="json-status">
        {parseError && <p className="form-error small">Not valid JSON yet: {parseError}</p>}
        {!parseError && shapeError && <p className="form-error small">{shapeError}. The previous draft is kept.</p>}
      </div>
      {!parseError && !shapeError && errors.length > 0 && (
        <ul className="field-errors">
          {errors.map((e, i) => <li key={i}><code>{e.field || "profile"}</code> {e.message}</li>)}
        </ul>
      )}
    </div>
  );
}

function HistoryTab({ history, current, canEdit, onLoad }: {
  history: PolicyVersion[]; current: number | null; canEdit: boolean; onLoad: (b: ProfileBody) => void;
}) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <ol className="versions">
      {history.map((v) => (
        <li key={v.id}>
          <div className="version-head">
            <span>
              <strong>{v.deleted ? "Deleted" : `Version ${v.version}`}</strong>
              {v.version === current && !v.deleted && <span className="pill">Current</span>}
              <span className="muted"> · {v.author} · {ago(v.created_at)}</span>
            </span>
            <span className="action-buttons">
              <button className="btn quiet" onClick={() => setOpen(open === v.id ? null : v.id)}>{open === v.id ? "Hide" : "View"}</button>
              {canEdit && !v.deleted && v.version !== current && <button className="btn" onClick={() => onLoad(v.body)}>Load into editor</button>}
            </span>
          </div>
          <p>“{v.comment}”</p>
          {open === v.id && <pre>{JSON.stringify(v.body, null, 2)}</pre>}
        </li>
      ))}
    </ol>
  );
}

function codes(items: string[]) {
  return items.map((x, i) => <span key={i}>{i > 0 && ", "}<code>{x}</code></span>);
}

function PlainSummary({ p }: { p: ProfileBody }) {
  const allowed = CLASSES.filter((c) => p.exec_allowed_classes.includes(c.id) && !p.exec_denied_classes.includes(c.id));
  const denied = CLASSES.filter((c) => p.exec_denied_classes.includes(c.id));
  const resp = p.response.on_violation;
  return (
    <ul className="plain-list">
      <li>
        <strong>Reads:</strong>{" "}
        {p.read_allowed === null ? "anything" : p.read_allowed.length === 0 ? "nothing" : <>only {codes(p.read_allowed)}</>}
        {p.protected_read.length > 0 && <>, never {codes(p.protected_read)}</>}.
      </li>
      <li><strong>Writes:</strong> {p.write_allowed.length === 0 ? "nothing" : <>only {codes(p.write_allowed)}</>}.</li>
      <li>
        <strong>Programs:</strong> {allowed.length === 0 ? "none" : allowed.map((c) => c.label.toLowerCase()).join(", ")}
        {denied.length > 0 && <>; explicitly not {denied.map((c) => c.label.toLowerCase()).join(", ")}</>}.
      </li>
      <li>
        <strong>Network:</strong>{" "}
        {p.egress_allowed.length === 0 && domainsOf(p).length === 0 ? "no outbound connections" : (
          <>
            only {codes([...p.egress_allowed, ...domainsOf(p)])}
            {domainsOf(p).length > 0 && <span className="muted"> (domains are resolved to addresses every 60 s; the engine checks addresses)</span>}
          </>
        )}.
      </li>
      {p.decoys.length > 0 && <li><strong>Tripwires:</strong> touching {codes(p.decoys)} is always a violation.</li>}
      <li className={p.mode === "ACTIVE_FREEZE_MODE" && resp !== "ALERT" ? "plain-bad" : ""}>
        <strong>Anything else:</strong>{" "}
        {p.mode === "SHADOW_MODE"
          ? <>opens an incident. Nothing is stopped{resp !== "ALERT" && <> (it would {responseLabel(resp).toLowerCase()} in active mode)</>}.</>
          : resp === "ALERT" ? "opens an incident. Nothing is stopped."
          : <>opens an incident and River3 will <strong>{responseLabel(resp).toLowerCase()}</strong> automatically when the evidence is verified.</>}
      </li>
    </ul>
  );
}
