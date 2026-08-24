import { useSyncExternalStore, type ReactNode } from "react";

import { authState, retryAuthOperation } from "@/lib/auth-state";

interface AuthBoundaryProps {
  children: ReactNode;
}

function DenialScreen({ referenceId }: { referenceId?: string }) {
  return (
    <main className="grid min-h-dvh place-items-center bg-background-base px-5 py-10 text-foreground">
      <section
        role="alert"
        aria-live="assertive"
        aria-labelledby="auth-denied-title"
        className="w-full max-w-xl border border-midground/40 bg-background p-8 shadow-2xl focus:outline-none sm:p-12"
        tabIndex={-1}
      >
        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.2em] text-midground">
          Hermes Agent
        </p>
        <h1 id="auth-denied-title" className="text-3xl font-bold leading-tight sm:text-4xl">
          Access denied
        </h1>
        <p className="mt-5 text-base leading-7 text-foreground/80">
          Your account is not authorized for this dashboard. Contact your organization’s
          administrator if you believe this is an error.
        </p>
        {referenceId && (
          <p className="mt-6 font-mono text-sm text-foreground/70">
            Support reference: {referenceId}
          </p>
        )}
      </section>
    </main>
  );
}

export function AuthBoundary({ children }: AuthBoundaryProps) {
  const state = useSyncExternalStore(authState.subscribe, authState.getSnapshot);

  if (state.status === "access_denied") {
    return <DenialScreen referenceId={state.referenceId} />;
  }

  if (state.status === "reauthenticating") {
    return (
      <main
        role="status"
        aria-live="polite"
        aria-busy="true"
        className="grid min-h-dvh place-items-center bg-background-base p-6 text-lg text-foreground"
      >
        Your session expired. Redirecting to sign in…
      </main>
    );
  }

  return (
    <>
      {children}
      {state.status === "provider_outage" && (
        <aside
          role="alert"
          aria-live="assertive"
          className="fixed inset-x-3 bottom-3 z-[100] mx-auto flex max-w-2xl flex-col gap-3 border border-amber-400 bg-[#170d02] p-4 text-base text-white shadow-2xl sm:flex-row sm:items-center sm:justify-between"
        >
          <div>
            <strong className="block text-amber-300">Sign-in provider unavailable</strong>
            <span>Your session is preserved. Retry when your identity provider recovers.</span>
          </div>
          <button
            type="button"
            onClick={() => void retryAuthOperation()}
            className="min-h-11 min-w-24 border border-amber-300 bg-amber-300 px-4 py-2 font-semibold text-[#170d02] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
          >
            Retry
          </button>
        </aside>
      )}
    </>
  );
}
