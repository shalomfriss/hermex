import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.HERMES_KANBAN_E2E_PORT ?? "9131");
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./e2e",
  testMatch: "kanban-accessibility.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: "list",
  outputDir: "test-results/kanban-accessibility",
  use: {
    baseURL,
    channel: process.env.HERMES_E2E_BROWSER_CHANNEL || undefined,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command:
      `rm -rf .playwright-kanban-home && mkdir -p .playwright-kanban-home && ` +
      `HERMES_HOME=$PWD/.playwright-kanban-home PYTHONPATH=.. ` +
      `${process.env.PYTHON ?? "python3"} e2e/kanban-server.py --port ${port}`,
    url: `${baseURL}/api/health`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [
    {
      name: "mobile-320",
      use: { ...devices["Desktop Chrome"], viewport: { width: 320, height: 700 } },
    },
    {
      name: "mobile-375",
      use: { ...devices["Desktop Chrome"], viewport: { width: 375, height: 812 } },
    },
    {
      name: "tablet-768",
      use: { ...devices["Desktop Chrome"], viewport: { width: 768, height: 1024 } },
    },
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
  ],
});
