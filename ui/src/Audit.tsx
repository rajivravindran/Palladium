import { useEffect, useState } from "react";
import { api } from "./api";
import { clock } from "./format";
import type { AuditRow } from "./types";

export function Audit({ token, tick, onError }: { token: string; tick: number; onError: (e: unknown) => void }) {
  const [rows, setRows] = useState<AuditRow[] | null>(null);

  // `tick` bumps on every live-stream message, so new audit rows (every action, decision and expiry
  // writes one) show up without a manual reload.
  useEffect(() => {
    let alive = true;
    api.audit(token).then((r) => alive && setRows(r)).catch(onError);
    return () => {
      alive = false;
    };
  }, [token, tick, onError]);

  if (!rows) return <section className="table-pane"><p className="muted">Loading…</p></section>;
  if (rows.length === 0) {
    return (
      <section className="table-pane empty">
        <p className="empty-title">Nothing recorded yet.</p>
        <p className="muted">Every operator action and automatic response lands here.</p>
      </section>
    );
  }

  return (
    <section className="table-pane" aria-label="Audit log">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td className="mono" title={new Date(r.ts).toLocaleString()}>{clock(r.ts)}</td>
              <td>{r.actor}</td>
              <td>{r.action}</td>
              <td className="mono">{r.target}</td>
              <td>
                {Object.keys(r.detail).length > 0 && (
                  <details>
                    <summary className="muted">{Object.keys(r.detail).length} field(s)</summary>
                    <pre className="mono">{JSON.stringify(r.detail, null, 2)}</pre>
                  </details>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
