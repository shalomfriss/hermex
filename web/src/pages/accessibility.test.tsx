// @vitest-environment jsdom

import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { I18nProvider } from "@/i18n";
import EnvPage from "./EnvPage";
import LogsPage from "./LogsPage";

const apiMocks = vi.hoisted(() => ({
  getEnvVars: vi.fn(),
  getLogs: vi.fn(),
}));

vi.mock("@/lib/api", () => ({ api: apiMocks }));
vi.mock("@/contexts/usePageHeader", () => ({
  usePageHeader: () => ({
    setAfterTitle: vi.fn(),
    setEnd: vi.fn(),
    setTitle: vi.fn(),
  }),
}));
vi.mock("@/components/OAuthProvidersCard", () => ({
  OAuthProvidersCard: () => null,
}));
vi.mock("@/plugins", () => ({ PluginSlot: () => null }));

let container: HTMLDivElement;
let root: Root;

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT =
  true;

async function render(ui: ReactNode) {
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
  await act(async () => root.render(<I18nProvider>{ui}</I18nProvider>));
}

beforeEach(() => {
  apiMocks.getLogs.mockResolvedValue({ lines: ["INFO dashboard ready"] });
  apiMocks.getEnvVars.mockResolvedValue({
    OPENROUTER_API_KEY: {
      advanced: false,
      category: "provider",
      description: "OpenRouter API key",
      is_password: true,
      is_set: false,
      redacted_value: null,
      tools: [],
      url: "https://openrouter.ai/keys",
    },
  });
});

afterEach(async () => {
  await act(async () => root?.unmount());
  container?.remove();
  vi.clearAllMocks();
});

describe("dashboard keyboard and interaction semantics", () => {
  it("makes log content a named keyboard-scroll region", async () => {
    await render(<LogsPage />);
    await vi.waitFor(() =>
      expect(container.textContent).toContain("INFO dashboard ready"),
    );

    const region = container.querySelector('[aria-label="agent.log — Logs"]');
    expect(region).toBeInstanceOf(HTMLDivElement);
    expect(region).toHaveProperty("tabIndex", 0);
  });

  it("keeps provider disclosure and row actions as sibling interactions", async () => {
    await render(<EnvPage />);
    await vi.waitFor(() =>
      expect(container.textContent).toContain("OpenRouter"),
    );

    expect(container.querySelector("button a, a button")).toBeNull();
    const disclosure = container.querySelector(
      'button[aria-expanded="false"]',
    ) as HTMLButtonElement | null;
    const keyLink = container.querySelector(
      'a[href="https://openrouter.ai/keys"]',
    );
    expect(disclosure).not.toBeNull();
    expect(keyLink).not.toBeNull();
    expect(disclosure?.parentElement).toBe(keyLink?.parentElement);
  });
});
