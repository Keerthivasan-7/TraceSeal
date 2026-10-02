import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  label: string;
}

interface State {
  error: Error | null;
}

// A screen-render crash with no boundary unmounts the whole React tree,
// leaving a silent blank page with no diagnostic shown to the operator —
// caught live when Investigate crashed on a legitimate `threshold: null`
// response (zero mark positions observed) it didn't expect. Scoped per
// screen, not around the whole app, so one screen's crash doesn't also
// discard every other screen's in-progress state (the same state App.tsx
// otherwise keeps alive across navigation).
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    console.error(`[${this.props.label}] crashed:`, error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="space-y-3 p-8 font-mono text-xs">
          <div className="uppercase tracking-widest text-danger">
            {this.props.label} hit an unexpected error
          </div>
          <div className="text-muted">{this.state.error.message}</div>
          <button
            onClick={() => this.setState({ error: null })}
            className="border border-line px-3 py-1.5 uppercase tracking-widest text-slate-300 hover:border-signal/40"
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
