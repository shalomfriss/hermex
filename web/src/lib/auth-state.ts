export interface AuthIdentity {
  displayName: string;
  providerLabel: string;
  organizationLabel: string;
}

export type AuthSnapshot =
  | { status: "authenticated"; identity?: AuthIdentity }
  | { status: "reauthenticating"; returnTo: string }
  | { status: "access_denied"; referenceId?: string }
  | { status: "provider_outage"; identity?: AuthIdentity }
  | { status: "logout_pending"; identity?: AuthIdentity }
  | { status: "logout_failed"; identity?: AuthIdentity };

type Listener = () => void;
type Retry = () => void | Promise<void>;

const INITIAL: AuthSnapshot = { status: "authenticated" };
let snapshot: AuthSnapshot = INITIAL;
let retryOperation: Retry | undefined;
const listeners = new Set<Listener>();

function emit(next: AuthSnapshot): void {
  snapshot = next;
  for (const listener of listeners) listener();
}

function currentIdentity(): AuthIdentity | undefined {
  return "identity" in snapshot ? snapshot.identity : undefined;
}

function safeReferenceId(body: unknown): string | undefined {
  if (!body || typeof body !== "object" || !("reference_id" in body)) return;
  const value = String(body.reference_id);
  return /^[A-Z0-9][A-Z0-9-]{2,31}$/.test(value) ? value : undefined;
}

function currentLocation(): string {
  return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

function loginUrlWithReturnTo(loginUrl: string, returnTo: string): string {
  const url = new URL(loginUrl, window.location.origin);
  url.searchParams.set("next", returnTo);
  return `${url.pathname}${url.search}${url.hash}`;
}

export const authState = {
  getSnapshot: (): AuthSnapshot => snapshot,
  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  authenticated(identity?: AuthIdentity): void {
    retryOperation = undefined;
    emit({ status: "authenticated", identity });
  },
  accessDenied(referenceId?: string): void {
    retryOperation = undefined;
    emit({ status: "access_denied", referenceId });
  },
  providerOutage(retry?: Retry): void {
    retryOperation = retry;
    emit({ status: "provider_outage", identity: currentIdentity() });
  },
  logoutPending(): void {
    emit({ status: "logout_pending", identity: currentIdentity() });
  },
  logoutFailed(): void {
    emit({ status: "logout_failed", identity: currentIdentity() });
  },
};

interface AuthFailureOptions {
  assign?: (url: string) => void;
  retry?: Retry;
}

export function applyAuthFailure(
  status: number,
  body: unknown,
  options: AuthFailureOptions = {},
): boolean {
  if (status === 401 && body && typeof body === "object") {
    const error = "error" in body ? String(body.error) : "";
    const loginUrl = "login_url" in body ? String(body.login_url) : "";
    if ((error === "unauthenticated" || error === "session_expired") && loginUrl) {
      const returnTo = currentLocation();
      try {
        sessionStorage.setItem("hermes.lastLocation", returnTo);
      } catch {
        // Storage may be unavailable in hardened/private browser contexts.
      }
      emit({ status: "reauthenticating", returnTo });
      (options.assign ?? window.location.assign.bind(window.location))(
        loginUrlWithReturnTo(loginUrl, returnTo),
      );
      return true;
    }
  }
  if (status === 403 && body && typeof body === "object" && "error" in body) {
    if (body.error === "access_denied") {
      authState.accessDenied(safeReferenceId(body));
      return true;
    }
  }
  if (status === 503 && body && typeof body === "object" && "error" in body) {
    if (body.error === "provider_unavailable") {
      authState.providerOutage(options.retry);
      return true;
    }
  }
  return false;
}

export async function retryAuthOperation(): Promise<void> {
  const retry = retryOperation;
  if (!retry) return;
  await retry();
  authState.authenticated(currentIdentity());
}

export function resetAuthStateForTests(): void {
  retryOperation = undefined;
  snapshot = INITIAL;
  listeners.clear();
}
