import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, ApiError, loadToken, saveToken } from "./api";
import { Approvals } from "./Approvals";
import { ErrorBoundary } from "./ErrorBoundary";
import { IncidentDetail } from "./IncidentDetail";
import { IncidentList, type ListFilter } from "./IncidentList";
import { Login, Mark } from "./Login";
import { Workloads } from "./Workloads";
import { Audit } from "./Audit";
import { Policies } from "./Policies";
import { ALL_TEAMS, inTeam, teamOptions } from "./TeamSelect";
import type { Incident, Stats } from "./types";

type View = "incidents" | "approvals" | "workloads" | "policies" | "audit";

interface Session {
  token: string;
  name: string;
  role: string;
  permissions: string[];
  /** CONTRACTS §6: empty = all teams */
  teams: string[];
}

export function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(() => loadToken() !== null);

  // Re-validate a token kept in sessionStorage from a previous page load.
  useEffect(() => {
    const t = loadToken();
    if (!t) return;
    api
      .me(t)
      .then((me) => setSession({
        token: t, name: me.operator, role: me.role, permissions: me.permissions ?? [],
        teams: Array.isArray(me.teams) ? me.teams : [],
      }))
      .catch(() => saveToken(null))
      .finally(() => setChecking(false));
  }, []);

  function login(token: string, name: string, role: string, permissions: string[], teams: string[]) {
    saveToken(token);
    setSession({ token, name, role, permissions, teams });
  }

  function logout() {
    saveToken(null);
    setSession(null);
  }

  if (checking) return <main className="login"><p className="muted">Restoring session…</p></main>;
  if (!session) return <Login onLogin={login} />;
  return <Console session={session} onLogout={logout} />;
}

function Console({ session, onLogout }: { session: Session; onLogout: () => void }) {
  const { token } = session;
  const [view, setView] = useState<View>("incidents");
  const [filter, setFilter] = useState<ListFilter>("attention");
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [live, setLive] = useState<"connecting" | "live" | "offline">("connecting");
  const [tick, setTick] = useState(0); // bumped on every live message; pages that aren't incidents reload on it
  const [team, setTeam] = useState<string>(ALL_TEAMS);

  const handleError = useCallback(
    (e: unknown) => {
      if (e instanceof ApiError && e.status === 401) onLogout();
      else setError(e instanceof Error ? e.message : String(e));
    },
    [onLogout],
  );

  const refresh = useCallback(async () => {
    try {
      const [list, s] = await Promise.all([api.incidents(token), api.stats(token)]);
      setIncidents(list);
      setStats(s);
      setError(null);
    } catch (e) {
      handleError(e);
    } finally {
      setLoading(false);
    }
  }, [token, handleError]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Live updates over SSE, with a polling fallback when the stream is down.
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  const lastTypeRef = useRef<string>("");
  useEffect(() => {
    let es: EventSource | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;

    const startPolling = () => {
      if (!poll) poll = setInterval(() => refreshRef.current(), 15_000);
    };
    const stopPolling = () => {
      if (poll) clearInterval(poll);
      poll = null;
    };

    const connect = async () => {
      if (stopped) return;
      try {
        es = await api.stream(token);
      } catch {
        setLive("offline");
        startPolling();
        retry = setTimeout(connect, 30_000);
        return;
      }
      es.onopen = () => {
        setLive("live");
        stopPolling();
      };
      // Generic: every message (`{"type": kind, "data": …}`; incident, workload, policy, drift,
      // approval, session, …) refreshes the incident list and stats and bumps `tick`, which every
      // other view watches. A new message type therefore needs no change here.
      es.onmessage = (m: MessageEvent<string>) => {
        try {
          const parsed = JSON.parse(m.data) as { type?: unknown };
          if (parsed && typeof parsed.type === "string") lastTypeRef.current = parsed.type;
        } catch {
          /* keep-alive or non-JSON frame: still a reason to refresh */
        }
        refreshRef.current();
        setTick((n) => n + 1);
      };
      es.onerror = () => {
        // The ticket is single-use, so the browser's auto-reconnect can't succeed; get a new one.
        es?.close();
        es = null;
        setLive("offline");
        startPolling();
        retry = setTimeout(connect, 5_000);
      };
    };
    connect();

    return () => {
      stopped = true;
      es?.close();
      stopPolling();
      if (retry) clearTimeout(retry);
    };
  }, [token]);

  const teams = useMemo(() => teamOptions(session.teams, incidents.map((i) => i.workload)), [session.teams, incidents]);
  const visible = incidents
    .filter((i) => filter !== "attention" || i.status === "open" || i.status === "contained")
    .filter((i) => inTeam(i.workload, team));
  const pendingApprovals = stats?.pending_approvals ?? 0;

  return (
    <div className="console">
      <header className="topbar">
        <div className="brand">
          <Mark size={22} />
          <span>River3</span>
        </div>
        <nav className="views" aria-label="Sections">
          <button className={view === "incidents" ? "active" : ""} onClick={() => setView("incidents")}>
            Incidents{stats && stats.open > 0 && <span className="count">{stats.open}</span>}
          </button>
          <button className={view === "approvals" ? "active" : ""} onClick={() => setView("approvals")}
            aria-label={`Approvals${pendingApprovals > 0 ? `, ${pendingApprovals} waiting` : ""}`}>
            Approvals{pendingApprovals > 0 && <span className="count">{pendingApprovals}</span>}
          </button>
          <button className={view === "workloads" ? "active" : ""} onClick={() => setView("workloads")}>
            Workloads
            {stats && stats.heading_out > 0 && <span className="count">{stats.heading_out}</span>}
            {stats && stats.frozen > 0 && <span className="count cold">{stats.frozen}</span>}
          </button>
          <button className={view === "policies" ? "active" : ""} onClick={() => setView("policies")}>
            Policies
          </button>
          <button className={view === "audit" ? "active" : ""} onClick={() => setView("audit")}>
            Audit log
          </button>
        </nav>
        <div className="session">
          <span className={`live live-${live}`}
            title={live === "live" ? `Receiving live updates${lastTypeRef.current ? ` (last: ${lastTypeRef.current})` : ""}` : "Live updates unavailable; refreshing every 15 s"}>
            {live === "live" ? "Live" : live === "connecting" ? "Connecting…" : "Polling"}
          </span>
          <span className="who">
            {session.name}
            {session.role && <span className="muted"> · {session.role}</span>}
          </span>
          {session.teams.length > 0 && (
            <span className="teams" aria-label="Your teams">
              {session.teams.map((t) => <span key={t} className="tag team">{t}</span>)}
            </span>
          )}
          <button className="btn quiet" onClick={onLogout}>Sign out</button>
        </div>
      </header>

      {stats && (
        <div className="stats" aria-label="Overview">
          <Stat label="Open" value={stats.open} tone={stats.open ? "warn" : undefined} />
          <Stat label="Critical open" value={stats.critical_open} tone={stats.critical_open ? "bad" : undefined} />
          <Stat label="Contained" value={stats.contained} />
          <Stat label="Workloads" value={stats.workloads} />
          <Stat label="Heading out of scope" value={stats.heading_out ?? 0} tone={stats.heading_out ? "warn" : undefined} />
          <Stat label="Frozen" value={stats.frozen} tone={stats.frozen ? "cold" : undefined} />
          <Stat label="Pending actions" value={stats.pending_actions} />
          {stats.pending_approvals !== undefined && (
            <Stat label="Pending approvals" value={pendingApprovals} tone={pendingApprovals ? "warn" : undefined} />
          )}
        </div>
      )}

      {error && (
        <div className="banner error" role="alert">
          {error} <button className="btn quiet" onClick={refresh}>Retry</button>
        </div>
      )}

      {view === "incidents" && (
        <div className="split">
          <IncidentList
            incidents={visible}
            selectedId={selectedId}
            filter={filter}
            onFilter={setFilter}
            onSelect={setSelectedId}
            loading={loading}
            team={team}
            teams={teams}
            onTeam={setTeam}
          />
          <ErrorBoundary label="Incident detail" resetKey={selectedId}>
            <IncidentDetail
              key={selectedId ?? "none"}
              token={token}
              incidentId={selectedId}
              onChanged={refresh}
              onError={handleError}
            />
          </ErrorBoundary>
        </div>
      )}
      {view === "approvals" && (
        <ErrorBoundary label="Approvals">
          <Approvals token={token} tick={tick} canAct={session.permissions.includes("act")} onError={handleError} />
        </ErrorBoundary>
      )}
      {view === "workloads" && (
        <ErrorBoundary label="Workloads">
          <Workloads token={token} tick={tick} canAct={session.permissions.includes("act")}
            canEditGate={session.permissions.includes("policies")} team={team} teams={teams} onTeam={setTeam}
            onError={handleError} />
        </ErrorBoundary>
      )}
      {view === "policies" && (
        <Policies token={token} canEdit={session.permissions.includes("policies")} tick={tick} onError={handleError} />
      )}
      {view === "audit" && <Audit token={token} tick={tick} onError={handleError} />}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "warn" | "bad" | "cold" }) {
  return (
    <div className={`stat${tone ? ` ${tone}` : ""}`}>
      <span className="stat-value">{value}</span>
      <span className="stat-label">{label}</span>
    </div>
  );
}
