// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { authState, resetAuthStateForTests } from "@/lib/auth-state";
import { AuthBoundary } from "./AuthBoundary";

let container: HTMLDivElement;
let root: Root;

beforeEach(() => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
    true;
  resetAuthStateForTests();
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

async function renderBoundary() {
  await act(async () => {
    root.render(
      <AuthBoundary>
        <div>dashboard content</div>
      </AuthBoundary>,
    );
  });
}

describe("AuthBoundary", () => {
  it("renders a terminal accessible denial without retry controls", async () => {
    authState.accessDenied("AUTH-7F4A");
    await renderBoundary();

    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain("Access denied");
    expect(alert?.textContent).toContain("AUTH-7F4A");
    expect(container.querySelector("button")).toBeNull();
    expect(container.textContent).not.toContain("finance-admins");
  });

  it("renders a retryable provider outage without discarding the page", async () => {
    const retry = vi.fn().mockResolvedValue(undefined);
    authState.authenticated({
      displayName: "Alice",
      providerLabel: "Company SSO",
      organizationLabel: "Acme",
    });
    authState.providerOutage(retry);
    await renderBoundary();

    expect(container.textContent).toContain("dashboard content");
    const button = container.querySelector("button");
    expect(button?.textContent).toContain("Retry");
    await act(async () => button?.click());
    expect(retry).toHaveBeenCalledTimes(1);
  });
});