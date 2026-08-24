type StorageLike = Pick<Storage, "getItem" | "removeItem" | "setItem">;

const TOKEN_RELOAD_STORAGE_KEY = "hermes.tokenReloadAttempted";

function dashboardAuthRequired(): boolean {
  return typeof window !== "undefined" && !!window.__HERMES_AUTH_REQUIRED__;
}

function reloadDashboardWindow(): void {
  if (typeof window !== "undefined") {
    window.location.reload();
  }
}

export function redirectDashboardToLogin(loginUrl?: string): void {
  if (typeof window === "undefined") return;
  const base = (window.__HERMES_BASE_PATH__ ?? "").replace(/\/$/, "");
  const next = `${window.location.pathname}${window.location.search}`;
  try {
    window.sessionStorage.setItem("hermes.lastLocation", next);
  } catch {
    /* privacy mode / blocked storage — best effort */
  }
  window.location.assign(
    loginUrl || `${base}/login?next=${encodeURIComponent(next)}`,
  );
}

function noteDashboardAuthDenial(code: number): void {
  // Surface-specific callers render the denial (PTY banner, events banner,
  // console line). This callback seam keeps the classification testable and
  // lets embedders add their own notice without turning denial into a reload.
  void code;
}

function dashboardSessionStorage(): StorageLike | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function clearDashboardTokenReloadAttempt(
  storage: StorageLike | null = dashboardSessionStorage(),
): void {
  try {
    storage?.removeItem(TOKEN_RELOAD_STORAGE_KEY);
  } catch {
    /* privacy mode / blocked storage — ignore */
  }
}

export function attemptDashboardTokenReloadOnce(
  storage: StorageLike | null = dashboardSessionStorage(),
  reload: () => void = reloadDashboardWindow,
): boolean {
  let alreadyReloaded = false;
  try {
    alreadyReloaded =
      storage?.getItem(TOKEN_RELOAD_STORAGE_KEY) === "1";
  } catch {
    /* privacy mode / blocked storage — fall through */
  }
  if (alreadyReloaded) {
    return false;
  }

  try {
    storage?.setItem(TOKEN_RELOAD_STORAGE_KEY, "1");
  } catch {
    /* privacy mode / blocked storage — best effort */
  }

  reload();
  return true;
}

export function maybeReloadForLoopbackWsAuthFailure(
  code: number,
  authRequired = dashboardAuthRequired(),
  storage: StorageLike | null = dashboardSessionStorage(),
  reload: () => void = reloadDashboardWindow,
  reauth: () => void = () => redirectDashboardToLogin(),
  denied: (code: number) => void = noteDashboardAuthDenial,
): boolean {
  if (code === 4403 || code === 4408) {
    denied(code);
    return false;
  }
  if (code !== 4401) {
    return false;
  }
  if (authRequired) {
    reauth();
    return true;
  }
  return attemptDashboardTokenReloadOnce(storage, reload);
}
