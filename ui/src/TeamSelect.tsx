import type { Workload } from "./types";

export const ALL_TEAMS = "";

/** Distinct, sorted team names from the operator's own teams plus whatever the workloads carry. */
export function teamOptions(base: string[] | undefined, workloads: Pick<Workload, "team">[]): string[] {
  const set = new Set<string>();
  for (const t of base ?? []) if (t) set.add(t);
  for (const w of workloads) if (w && w.team) set.add(w.team);
  return [...set].sort((a, b) => a.localeCompare(b));
}

export function inTeam(w: Pick<Workload, "team"> | null | undefined, team: string): boolean {
  return team === ALL_TEAMS || (w?.team ?? "") === team;
}

/**
 * Client-side team filter (CONTRACTS §6). The API already scopes reads to the operator's teams;
 * this only narrows what is on screen. Hidden when there is nothing to choose between.
 */
export function TeamSelect({ id, teams, value, onChange }: {
  id: string; teams: string[]; value: string; onChange: (team: string) => void;
}) {
  if (teams.length === 0 && value === ALL_TEAMS) return null;
  return (
    <label className="team-filter" htmlFor={id}>
      <span className="muted small">Team</span>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} aria-label="Filter by team">
        <option value={ALL_TEAMS}>All teams</option>
        {teams.map((t) => <option key={t} value={t}>{t}</option>)}
        {value !== ALL_TEAMS && !teams.includes(value) && <option value={value}>{value}</option>}
      </select>
    </label>
  );
}
