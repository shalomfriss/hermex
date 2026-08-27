// @vitest-environment jsdom
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AutoField } from "./AutoField";
import { SkillRow } from "@/pages/SkillsPage";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

async function render(ui: ReactNode) {
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(ui));
}

afterEach(async () => {
  await act(async () => root?.unmount());
  container?.remove();
});

describe("dashboard accessible control names", () => {
  it.each([
    ["agent.enabled", { type: "boolean" }, true],
    ["agent.provider", { type: "select", options: ["openrouter"] }, "openrouter"],
    ["agent.max_iterations", { type: "number" }, 10],
    ["agent.system_prompt", { type: "text" }, "Be useful"],
    ["agent.enabled_toolsets", { type: "list" }, ["web"]],
    ["agent.model", { type: "string" }, "hermes"],
  ])("associates %s with a unique full-path name", async (schemaKey, schema, value) => {
    await render(
      <AutoField
        schemaKey={schemaKey}
        schema={schema}
        value={value}
        onChange={vi.fn()}
      />,
    );

    const control = container.querySelector<HTMLElement>(
      "input, textarea, select, button[role='switch'], button[role='combobox']",
    );
    expect(control).not.toBeNull();
    expect(control?.getAttribute("aria-label")).toBe(
      schemaKey.replace(/[._-]+/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()),
    );
  });

  it("names each nested config input from its full value path", async () => {
    await render(
      <AutoField
        schemaKey="cron.delivery"
        schema={{ type: "object" }}
        value={{ target: "local", retry: { count: 2 } }}
        onChange={vi.fn()}
      />,
    );

    expect(
      Array.from(container.querySelectorAll("input"), (input) => input.getAttribute("aria-label")),
    ).toEqual(["Cron Delivery Target", "Cron Delivery Retry Count"]);
  });

  it("names a skill toggle with both the action and skill name", async () => {
    await render(
      <SkillRow
        skill={{ name: "grounded-citations", description: "Cite sources.", enabled: true } as never}
        toggling={false}
        onToggle={vi.fn()}
        onEdit={vi.fn()}
        noDescriptionLabel="No description"
      />,
    );

    const toggle = container.querySelector<HTMLElement>("button[role='switch']");
    expect(toggle?.getAttribute("aria-label")).toBe("Disable grounded-citations");
  });
});
