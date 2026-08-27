import { describe, expect, it, vi } from "vitest";

import { openConsoleSocket } from "./console-reconnect";


describe("openConsoleSocket", () => {
  it("mints a fresh URL for every console reconnect", async () => {
    const buildUrl = vi
      .fn()
      .mockResolvedValueOnce("wss://example/api/console?ticket=first")
      .mockResolvedValueOnce("wss://example/api/console?ticket=second");
    const createSocket = vi.fn((url: string) => ({ url }));

    const first = await openConsoleSocket(buildUrl, createSocket, "coder");
    const second = await openConsoleSocket(buildUrl, createSocket, "coder");

    expect(buildUrl).toHaveBeenCalledTimes(2);
    expect(buildUrl).toHaveBeenNthCalledWith(1, "/api/console", {
      profile: "coder",
    });
    expect(first.url).toContain("ticket=first");
    expect(second.url).toContain("ticket=second");
  });
});
