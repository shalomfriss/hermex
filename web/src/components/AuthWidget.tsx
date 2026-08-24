/**
 * AuthWidget — sidebar "Logged in as …" affordance for the dashboard
 * OAuth gate (Phase 7 of .hermes/plans/2026-05-21-dashboard-oauth-auth.md).
 *
 * Renders nothing in loopback / --insecure mode. In gated mode, fetches
 * /api/auth/me on mount and surfaces:
 *
 *   - a friendly display name/email when available, otherwise a generic
 *     account label (opaque provider subject IDs are never rendered)
 *   - the provider's display_name (looked up from /api/auth/providers,
 *     defaults to the bare provider key)
 *   - a logout button that POSTs /auth/logout and full-page-navigates to
 *     /login (the dashboard becomes inaccessible again)
 *
 * Failure modes:
 *   - 401 from /api/auth/me means we're not gated (or the gate is on but
 *     we have no cookie — in that case the gate's middleware would have
 *     redirected us before App.tsx renders, so we won't see this). The
 *     widget renders nothing.
 *   - Network error: shows a minimal "auth status unavailable" message
 *     so the user knows the widget tried.
 */

import { useEffect, useState, useSyncExternalStore } from "react";
import { ApiError, api, type AuthMeResponse } from "@/lib/api";
import { authState } from "@/lib/auth-state";
import { cn } from "@/lib/utils";
import { LogOut } from "lucide-react";

interface AuthWidgetProps {
  className?: string;
  collapsed?: boolean;
}

export function AuthWidget({ className, collapsed = false }: AuthWidgetProps) {
  const [me, setMe] = useState<AuthMeResponse | null>(null);
  const [hidden, setHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const globalAuth = useSyncExternalStore(authState.subscribe, authState.getSnapshot);

  // Loopback / --insecure mode: the auth gate is off, so /api/auth/me is a
  // guaranteed 401. Don't fire the request at all — it only produces console
  // noise ("Failed to load resource: 401") on every dashboard load.
  const gated =
    typeof window !== "undefined" && !!window.__HERMES_AUTH_REQUIRED__;

  useEffect(() => {
    if (!gated) return;
    let cancelled = false;
    api
      .getAuthMe()
      .then((data) => {
        if (cancelled) return;
        setMe(data);
        authState.authenticated({
          displayName: data.display_name || data.email || "Signed-in account",
          providerLabel: data.provider_display_name || data.provider,
          organizationLabel: data.organization_label,
        });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // 401 from /api/auth/me means the gate isn't engaged in this
        // process (loopback mode) — render nothing. fetchJSON throws an
        // Error with the status code as a prefix; the global 401
        // handler only redirects on the structured envelope, so a plain
        // 401 from /api/auth/me with no envelope bubbles up here.
        if (
          err instanceof ApiError &&
          err.status === 403 &&
          typeof err.body === "object" &&
          err.body !== null &&
          "error" in err.body &&
          err.body.error === "access_denied"
        ) {
          setError("Your account is not authorized for this dashboard");
          return;
        }
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.startsWith("401:") || msg.startsWith("403:")) {
          setHidden(true);
          return;
        }
        setError("auth status unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [gated]);

  // Nothing to show in ungated mode — there is no logged-in identity.
  if (!gated) return null;

  if (hidden) return null;

  if (error) {
    return (
      <div
        role="alert"
        aria-live="assertive"
        className={cn(
          "px-5 py-2 text-[0.65rem] tracking-[0.05em] text-muted-foreground/70",
          className,
        )}
      >
        {error}
      </div>
    );
  }

  if (!me) {
    // Loading. Reserve the row height so the sidebar doesn't flicker
    // when the data arrives.
    return (
      <div
        className={cn(
          "h-9 px-5 py-2 text-[0.65rem] text-muted-foreground/40",
          className,
        )}
        aria-busy="true"
      >
        …
      </div>
    );
  }

  const handleLogout = async () => {
    setError(null);
    try {
      await api.logout();
    } catch {
      setError("Sign out failed. Your session is still active; please try again.");
    }
  };

  // Never fall back to the provider's opaque subject identifier. It is not a
  // friendly identity and disclosing it in UI/support screenshots adds risk.
  const label = me.display_name || me.email || "Signed-in account";
  const providerLabel = me.provider_display_name || me.provider;
  const logoutPending = globalAuth.status === "logout_pending";

  if (collapsed) {
    return (
      <button
        type="button"
        onClick={() => void handleLogout()}
        disabled={logoutPending}
        className="mx-auto flex min-h-11 min-w-11 items-center justify-center text-muted-foreground hover:text-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-current disabled:opacity-60"
        aria-label={logoutPending ? "Signing out" : "Log out"}
        title={logoutPending ? "Signing out…" : "Log out"}
      >
        <LogOut className="h-4 w-4" />
      </button>
    );
  }

  return (
    <div
      className={cn(
        "flex shrink-0 items-center justify-between gap-2",
        "px-5 py-2",
        "border-t border-current/10",
        "text-[0.65rem] tracking-[0.05em]",
        className,
      )}
      role="status"
      aria-label={`Logged in as ${label}`}
    >
      <div className="flex min-w-0 flex-col">
        <span className="truncate text-sm text-foreground/90">
          {label}
        </span>
        <span className="truncate text-muted-foreground/70">
          via {providerLabel}
        </span>
        {me.organization_label && (
          <span className="truncate text-muted-foreground/70">
            {me.organization_label}
          </span>
        )}
      </div>
      <button
        type="button"
        onClick={() => void handleLogout()}
        disabled={logoutPending}
        className={cn(
          "flex min-h-11 min-w-11 shrink-0 items-center justify-center rounded text-muted-foreground/70",
          "transition-colors hover:bg-current/10 hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-current/40",
        )}
        aria-label={logoutPending ? "Signing out" : "Log out"}
        title={logoutPending ? "Signing out…" : "Log out"}
      >
        <LogOut className="h-4 w-4" />
      </button>
    </div>
  );
}
