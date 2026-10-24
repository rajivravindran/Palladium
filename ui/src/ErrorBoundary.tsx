import { Component, type ErrorInfo, type ReactNode } from "react";

/**
 * Catches a render error in one pane so the rest of the console stays usable. The fallback
 * card names the pane and offers to remount it; `resetKey` changing (a different incident,
 * policy or view) also clears the error.
 */
export class ErrorBoundary extends Component<
  { children: ReactNode; label: string; resetKey?: string | number | null },
  { error: Error | null; generation: number }
> {
  state = { error: null as Error | null, generation: 0 };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[river3 console] ${this.props.label} failed to render`, error, info.componentStack);
  }

  componentDidUpdate(prev: { resetKey?: string | number | null }) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.reset();
  }

  reset = () => this.setState((s) => ({ error: null, generation: s.generation + 1 }));

  render() {
    if (this.state.error) {
      return (
        <section className="detail-pane error-card" role="alert" aria-label={`${this.props.label} failed`}>
          <p className="empty-title">The {this.props.label.toLowerCase()} hit an error and stopped drawing.</p>
          <p className="muted small">Nothing was sent to the API. Your last saved state is unaffected.</p>
          <pre className="mono small">{this.state.error.message}</pre>
          <div className="action-buttons">
            <button className="btn primary" onClick={this.reset}>Reload {this.props.label.toLowerCase()}</button>
          </div>
        </section>
      );
    }
    // A new key remounts the children so their state starts clean after a reload.
    return <div key={this.state.generation} className="boundary">{this.props.children}</div>;
  }
}
