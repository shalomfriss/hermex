// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GatewayClient } from "./gatewayClient";

const reloadMocks = vi.hoisted(() => ({
  maybeReloadForLoopbackWsAuthFailure: vi.fn(() => false),
}));

vi.mock("./dashboard-auth-reload", () => ({
  maybeReloadForLoopbackWsAuthFailure:
    reloadMocks.maybeReloadForLoopbackWsAuthFailure,
  redirectDashboardToLogin: vi.fn(),
}));

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];
  static OPEN = 1;

  listeners = new Map<string, Array<(event: EventLike) => void>>();
  readyState = 0;
  url: string;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, cb: (event: EventLike) => void) {
    const list = this.listeners.get(type) ?? [];
    list.push(cb);
    this.listeners.set(type, list);
  }

  close() {}

  emit(type: string, event: EventLike) {
    for (const cb of this.listeners.get(type) ?? []) {
      cb(event);
    }
  }

  removeEventListener(type: string, cb: (event: EventLike) => void) {
    const list = this.listeners.get(type) ?? [];
    this.listeners.set(
      type,
      list.filter((item) => item !== cb),
    );
  }

  send() {}
}

type EventLike = {
  code?: number;
};

beforeEach(() => {
  FakeWebSocket.instances = [];
  reloadMocks.maybeReloadForLoopbackWsAuthFailure.mockReset();
  reloadMocks.maybeReloadForLoopbackWsAuthFailure.mockReturnValue(false);
  vi.stubGlobal("WebSocket", FakeWebSocket);
  Object.defineProperty(window, "__HERMES_SESSION_TOKEN__", {
    configurable: true,
    value: "stale-token",
    writable: true,
  });
  Object.defineProperty(window, "__HERMES_AUTH_REQUIRED__", {
    configurable: true,
    value: false,
    writable: true,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("GatewayClient", () => {
  it("treats loopback 4401 closes as stale-token reload candidates", async () => {
    reloadMocks.maybeReloadForLoopbackWsAuthFailure.mockReturnValue(true);
    const gw = new GatewayClient();
    const connectPromise = gw.connect();

    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    const socket = FakeWebSocket.instances[0];
    socket.readyState = 1;
    socket.emit("open", {});
    await connectPromise;

    socket.emit("close", { code: 4401 });

    expect(
      reloadMocks.maybeReloadForLoopbackWsAuthFailure,
    ).toHaveBeenCalledWith(4401);
    expect(gw.connectionState).toBe("open");
  });

  it("mints a fresh ticket for a JSON-RPC reconnect", async () => {
    window.__HERMES_AUTH_REQUIRED__ = true;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ ticket: "first", ttl_seconds: 30 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ ticket: "second", ttl_seconds: 30 }),
      });
    vi.stubGlobal("fetch", fetchMock);
    const gw = new GatewayClient();

    const firstConnect = gw.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    FakeWebSocket.instances[0].readyState = 1;
    FakeWebSocket.instances[0].emit("open", {});
    await firstConnect;
    FakeWebSocket.instances[0].emit("close", { code: 1006 });

    const secondConnect = gw.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(2));
    FakeWebSocket.instances[1].readyState = 1;
    FakeWebSocket.instances[1].emit("open", {});
    await secondConnect;

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(FakeWebSocket.instances[0].url).toContain("ticket=first");
    expect(FakeWebSocket.instances[1].url).toContain("ticket=second");
  });

  it("surfaces JSON-RPC denial closes without reconnecting", async () => {
    const onAuthDenied = vi.fn();
    const gw = new GatewayClient(onAuthDenied);
    const connectPromise = gw.connect();
    await vi.waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1));
    FakeWebSocket.instances[0].readyState = 1;
    FakeWebSocket.instances[0].emit("open", {});
    await connectPromise;

    FakeWebSocket.instances[0].emit("close", { code: 4403 });

    expect(onAuthDenied).toHaveBeenCalledWith(4403);
    expect(gw.connectionState).toBe("closed");
  });
});
