import { Component, type ErrorInfo, type ReactNode } from "react";

const CHUNK_RELOAD_KEY = "hermes:chunk-reload-attempted";
const CHUNK_ERROR_PATTERNS = [
  /chunkloaderror/i,
  /loading chunk [\d-]+ failed/i,
  /failed to fetch dynamically imported module/i,
  /importing a module script failed/i,
];

interface DashboardErrorBoundaryProps {
  children: ReactNode;
  reloadPage?: () => void;
  healthyResetMs?: number;
}

interface DashboardErrorBoundaryState {
  error: Error | null;
}

function isStaleChunkError(error: Error): boolean {
  return CHUNK_ERROR_PATTERNS.some((pattern) => pattern.test(error.message));
}

function readReloadGuard(): boolean {
  try {
    return sessionStorage.getItem(CHUNK_RELOAD_KEY) === "1";
  } catch {
    return true;
  }
}

function setReloadGuard(): void {
  try {
    sessionStorage.setItem(CHUNK_RELOAD_KEY, "1");
  } catch {
    // Storage can be unavailable in private/locked-down browser contexts.
  }
}

function clearReloadGuard(): void {
  try {
    sessionStorage.removeItem(CHUNK_RELOAD_KEY);
  } catch {
    // Recovery controls remain usable even when storage is unavailable.
  }
}

export class DashboardErrorBoundary extends Component<
  DashboardErrorBoundaryProps,
  DashboardErrorBoundaryState
> {
  state: DashboardErrorBoundaryState = { error: null };
  private healthyTimer: ReturnType<typeof setTimeout> | undefined;

  static getDerivedStateFromError(error: Error): Partial<DashboardErrorBoundaryState> {
    return { error };
  }

  componentDidMount(): void {
    this.armHealthyReset();
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Dashboard render failed", error, info.componentStack);
    if (isStaleChunkError(error) && !readReloadGuard()) {
      setReloadGuard();
      (this.props.reloadPage ?? (() => window.location.reload()))();
    }
  }

  componentDidUpdate(
    _previousProps: DashboardErrorBoundaryProps,
    previousState: DashboardErrorBoundaryState,
  ): void {
    if (previousState.error && !this.state.error) this.armHealthyReset();
  }

  componentWillUnmount(): void {
    if (this.healthyTimer) clearTimeout(this.healthyTimer);
  }

  private armHealthyReset(): void {
    if (this.state.error) return;
    if (this.healthyTimer) clearTimeout(this.healthyTimer);
    this.healthyTimer = setTimeout(
      clearReloadGuard,
      this.props.healthyResetMs ?? 30_000,
    );
  }

  private retry = (): void => {
    this.setState({ error: null });
  };

  private reload = (): void => {
    (this.props.reloadPage ?? (() => window.location.reload()))();
  };

  render(): ReactNode {
    if (!this.state.error) {
      return this.props.children;
    }

    return (
      <main className="grid min-h-dvh place-items-center bg-background-base px-5 py-10 text-foreground">
        <section
          role="alert"
          aria-live="assertive"
          aria-labelledby="dashboard-error-title"
          className="w-full max-w-xl border border-midground/40 bg-background p-8 shadow-2xl sm:p-12"
        >
          <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-midground">
            Hermes Agent
          </p>
          <h1 id="dashboard-error-title" className="text-3xl font-bold leading-tight sm:text-4xl">
            Dashboard could not load
          </h1>
          <p className="mt-5 text-base leading-7 text-foreground/80">
            The dashboard hit an unexpected error. Try again without leaving this page, or reload
            to fetch the latest application files.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <button
              type="button"
              onClick={this.retry}
              className="min-h-11 border border-foreground bg-foreground px-5 py-2 font-semibold text-background focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
            >
              Try again
            </button>
            <button
              type="button"
              onClick={this.reload}
              className="min-h-11 border border-midground px-5 py-2 font-semibold focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2"
            >
              Reload
            </button>
          </div>
        </section>
      </main>
    );
  }
}
