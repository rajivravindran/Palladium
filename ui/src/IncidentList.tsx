import type { Incident } from "./types";
import { ago, severityLabel, stateLabel, statusLabel } from "./format";
import { TeamSelect } from "./TeamSelect";

export type ListFilter = "attention" | "all";

export function IncidentList({
  incidents, selectedId, filter, onFilter, onSelect, loading, team, teams, onTeam,
}: {
  incidents: Incident[];
  selectedId: string | null;
  filter: ListFilter;
  onFilter: (f: ListFilter) => void;
  onSelect: (id: string) => void;
  loading: boolean;
  /** client-side team filter; "" = all */
  team: string;
  teams: string[];
  onTeam: (t: string) => void;
}) {
  return (
    <section className="list-pane" aria-label="Incidents">
      <div className="segmented" role="tablist" aria-label="Which incidents">
        <button role="tab" aria-selected={filter === "attention"} onClick={() => onFilter("attention")}>
          Needs attention
        </button>
        <button role="tab" aria-selected={filter === "all"} onClick={() => onFilter("all")}>
          All
        </button>
      </div>

      {(teams.length > 0 || team !== "") && (
        <div className="pad">
          <TeamSelect id="team-incidents" teams={teams} value={team} onChange={onTeam} />
        </div>
      )}

      {!loading && incidents.length === 0 && (
        <div className="empty">
          <p className="empty-title">
            {team !== "" ? `No incidents for team ${team}.` : filter === "attention" ? "Nothing needs you right now." : "No incidents yet."}
          </p>
          <p className="muted">
            Incidents appear here as soon as your policy layer posts them to <code>/api/v1/incidents</code>.
          </p>
        </div>
      )}

      <ol className="incident-list">
        {incidents.map((i) => (
          <li key={i.id}>
            <button
              className={`incident-row sev-${i.severity}${i.id === selectedId ? " selected" : ""}`}
              onClick={() => onSelect(i.id)}
              aria-current={i.id === selectedId ? "true" : undefined}
            >
              <span className="row-top">
                <span className={`sev-pill sev-${i.severity}`}>{severityLabel[i.severity]}</span>
                <span className="row-time">{ago(i.created_at)}</span>
              </span>
              <span className="row-title">{i.title}</span>
              <span className="row-meta">
                <span>{i.workload.name}{i.workload.team && teams.length > 1 && <span className="muted"> · {i.workload.team}</span>}</span>
                <span className={`state-dot state-${i.workload.state}`}>{stateLabel[i.workload.state]}</span>
              </span>
              <span className="row-status">
                {statusLabel[i.status]}
                {i.mode === "shadow" && <span className="tag">Shadow</span>}
                {i.demo && <span className="tag demo">Demo</span>}
              </span>
            </button>
          </li>
        ))}
      </ol>
    </section>
  );
}
