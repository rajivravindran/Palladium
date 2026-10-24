import { useState } from "react";
import { api } from "./api";

export function Login({ onLogin }: {
  onLogin: (token: string, name: string, role: string, permissions: string[], teams: string[]) => void;
}) {
  const [token, setToken] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const me = await api.me(token.trim());
      onLogin(token.trim(), me.operator, me.role, me.permissions ?? [], Array.isArray(me.teams) ? me.teams : []);
    } catch {
      setError("That operator token wasn't accepted. Ask your River3 admin to check the principals file.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit}>
        <Mark />
        <h1>River3</h1>
        <p className="muted">Sign in with your operator token. Every action you take is recorded under your name.</p>
        <label htmlFor="token">Operator token</label>
        <input id="token" type="password" autoComplete="current-password" value={token}
          onChange={(e) => setToken(e.target.value)} autoFocus />
        {error && <p className="form-error" role="alert">{error}</p>}
        <button className="btn primary" disabled={!token.trim() || busy}>{busy ? "Checking…" : "Sign in"}</button>
      </form>
    </main>
  );
}

export function Mark({ size = 28 }: { size?: number }) {
  // A two-aspect signal head: red = stop, blue = held/frozen.
  return (
    <svg className="mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect x="6" y="2" width="20" height="28" rx="4" fill="var(--ink)" />
      <circle cx="16" cy="11" r="4.5" fill="var(--signal)" />
      <circle cx="16" cy="21.5" r="4.5" fill="var(--ice)" />
    </svg>
  );
}
