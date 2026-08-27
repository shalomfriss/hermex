import { describe, expect, it, vi } from "vitest";

import {
  attemptDashboardTokenReloadOnce,
  clearDashboardTokenReloadAttempt,
  maybeReloadForLoopbackWsAuthFailure,
} from "./dashboard-auth-reload";

function makeStorage() {
  const values = new Map<string, string>();
  return {
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
    },
    setItem(key: string, value: string) {
      values.set(key, value);
    },
  };
}

describe("attemptDashboardTokenReloadOnce", () => {
  it("reloads once and latches the attempt", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(attemptDashboardTokenReloadOnce(storage, reload)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);

    expect(attemptDashboardTokenReloadOnce(storage, reload)).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("clears the latch when asked", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(attemptDashboardTokenReloadOnce(storage, reload)).toBe(true);
    clearDashboardTokenReloadAttempt(storage);
    expect(attemptDashboardTokenReloadOnce(storage, reload)).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });
});

describe("maybeReloadForLoopbackWsAuthFailure", () => {
  it("reloads once for loopback 4401 closes", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(
      maybeReloadForLoopbackWsAuthFailure(4401, false, storage, reload),
    ).toBe(true);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("does not reload for non-auth close codes", () => {
    const storage = makeStorage();
    const reload = vi.fn();

    expect(
      maybeReloadForLoopbackWsAuthFailure(1006, false, storage, reload),
    ).toBe(false);
    expect(reload).not.toHaveBeenCalled();
  });

  it("transitions gated 4401 closes to reauthentication without reload", () => {
    const reload = vi.fn();
    const reauth = vi.fn();

    expect(
      maybeReloadForLoopbackWsAuthFailure(
        4401,
        true,
        makeStorage(),
        reload,
        reauth,
      ),
    ).toBe(true);
    expect(reauth).toHaveBeenCalledTimes(1);
    expect(reload).not.toHaveBeenCalled();
  });

  it.each([4403, 4408])("transitions %s closes to denial UX", (code) => {
    const denied = vi.fn();

    expect(
      maybeReloadForLoopbackWsAuthFailure(
        code,
        true,
        makeStorage(),
        vi.fn(),
        vi.fn(),
        denied,
      ),
    ).toBe(false);
    expect(denied).toHaveBeenCalledWith(code);
  });
});
