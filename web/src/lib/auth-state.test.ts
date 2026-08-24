// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyAuthFailure,
  authState,
  resetAuthStateForTests,
  retryAuthOperation,
} from "./auth-state";

beforeEach(() => {
  resetAuthStateForTests();
  window.history.replaceState(null, "", "/hermes/sessions/abc?tab=messages#latest");
  Object.defineProperty(window, "__HERMES_BASE_PATH__", {
    configurable: true,
    value: "/hermes",
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe("global dashboard auth state", () => {
  it("preserves the exact route and redirects a 401 through the prefixed login", () => {
    const assign = vi.fn();

    applyAuthFailure(
      401,
      { error: "session_expired", login_url: "/hermes/login" },
      { assign },
    );

    expect(authState.getSnapshot().status).toBe("reauthenticating");
    expect(sessionStorage.getItem("hermes.lastLocation")).toBe(
      "/hermes/sessions/abc?tab=messages#latest",
    );
    expect(assign).toHaveBeenCalledWith(
      "/hermes/login?next=%2Fhermes%2Fsessions%2Fabc%3Ftab%3Dmessages%23latest",
    );
  });

  it("makes 403 terminal without exposing provider policy details", () => {
    applyAuthFailure(403, {
      error: "access_denied",
      detail: "group_required: finance-admins",
      reference_id: "AUTH-7F4A",
    });

    expect(authState.getSnapshot()).toEqual({
      status: "access_denied",
      referenceId: "AUTH-7F4A",
    });
  });

  it("makes 503 retryable while retaining the authenticated identity", async () => {
    authState.authenticated({
      displayName: "Alice",
      providerLabel: "Company SSO",
      organizationLabel: "Acme",
    });
    const retry = vi.fn().mockResolvedValue(undefined);

    applyAuthFailure(503, { error: "provider_unavailable" }, { retry });

    expect(authState.getSnapshot()).toMatchObject({
      status: "provider_outage",
      identity: { displayName: "Alice" },
    });
    await retryAuthOperation();
    expect(retry).toHaveBeenCalledTimes(1);
  });
});