// @vitest-environment jsdom

import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DashboardErrorBoundary } from "./DashboardErrorBoundary";

let container: HTMLDivElement;
let root: Root;

async function render(ui: ReactNode) {
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(ui));
}

beforeEach(() => {
  sessionStorage.clear();
});

afterEach(async () => {
  await act(async () => root?.unmount());
  container?.remove();
  vi.restoreAllMocks();
});

function Broken({ message = "render failed" }: { message?: string }): ReactNode {
  throw new Error(message);
}

describe("DashboardErrorBoundary", () => {
  it("shows an accessible recovery screen for render failures and retries children", async () => {
    let broken = true;
    function Child() {
      if (broken) throw new Error("render failed");
      return <p>Dashboard recovered</p>;
    }

    await render(
      <DashboardErrorBoundary reloadPage={vi.fn()}>
        <Child />
      </DashboardErrorBoundary>,
    );

    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain("Dashboard could not load");
    const buttons = Array.from(container.querySelectorAll("button"));
    expect(buttons.map((button) => button.textContent)).toEqual(["Try again", "Reload"]);

    broken = false;
    await act(async () => buttons[0].click());
    expect(container.textContent).toContain("Dashboard recovered");
  });

  it("reloads once for a stale lazy chunk and then renders recovery controls", async () => {
    const reloadPage = vi.fn();
    const chunkError = "Failed to fetch dynamically imported module: /assets/page-old.js";

    await render(
      <DashboardErrorBoundary reloadPage={reloadPage}>
        <Broken message={chunkError} />
      </DashboardErrorBoundary>,
    );
    expect(reloadPage).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem("hermes:chunk-reload-attempted")).toBe("1");

    await act(async () => root.unmount());
    root = createRoot(container);
    await act(async () =>
      root.render(
        <DashboardErrorBoundary reloadPage={reloadPage}>
          <Broken message={chunkError} />
        </DashboardErrorBoundary>,
      ),
    );

    expect(reloadPage).toHaveBeenCalledTimes(1);
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      "Dashboard could not load",
    );
  });

  it("clears the stale-chunk reload guard after a successful render", async () => {
    sessionStorage.setItem("hermes:chunk-reload-attempted", "1");
    await render(
      <DashboardErrorBoundary reloadPage={vi.fn()} healthyResetMs={0}>
        <p>Healthy dashboard</p>
      </DashboardErrorBoundary>,
    );
    await act(async () => new Promise((resolve) => setTimeout(resolve, 0)));
    expect(sessionStorage.getItem("hermes:chunk-reload-attempted")).toBeNull();
  });
});
