// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthWidget } from "./AuthWidget";

let container: HTMLDivElement;
let root: Root;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
    true;
  window.__HERMES_AUTH_REQUIRED__ = true;
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  if (root) await act(async () => root.unmount());
  container?.remove();
  vi.unstubAllGlobals();
  delete window.__HERMES_AUTH_REQUIRED__;
});

async function renderWidget() {
  await act(async () => {
    root.render(<AuthWidget />);
  });
  await act(async () => {
    await Promise.resolve();
  });
}

describe("AuthWidget enterprise authorization states", () => {
  it("renders the verified identity and provider", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(200, {
          user_id: "user-123",
          email: "alice@example.com",
          display_name: "Alice Example",
          org_id: "tenant-a",
          provider: "self-hosted",
          expires_at: 2_000_000_000,
        }),
      ),
    );

    await renderWidget();

    expect(container.textContent).toContain("Alice Example");
    expect(container.textContent).toContain("via self-hosted");
  });

  it("renders a generic authorization failure for structured 403 responses", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(403, {
          error: "access_denied",
          detail: "Your account is not authorized for this dashboard.",
        }),
      ),
    );

    await renderWidget();

    expect(container.textContent).toContain(
      "Your account is not authorized for this dashboard",
    );
    expect(container.textContent).not.toContain("group_required");
  });
});
