import { describe, expect, it, vi } from "vitest";

import { getWsTicket } from "./api";


describe("getWsTicket", () => {
  it("transitions a ticket-mint 401 to the server-provided reauth URL", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({
          error: "session_expired",
          login_url: "/login?next=%2Fchat",
        }),
        { status: 401, headers: { "content-type": "application/json" } },
      ),
    );
    const reauth = vi.fn();

    const pending = getWsTicket(fetchImpl, reauth);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(reauth).toHaveBeenCalledWith("/login?next=%2Fchat");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    void pending;
  });
});
