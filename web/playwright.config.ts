import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.HERMES_E2E_PORT ?? "9129");
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./e2e",
  testMatch: "enterprise-sso.spec.ts",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }],
    ["json", { outputFile: "playwright-report/results.json" }],
  ],
  outputDir: "test-results",
  use: {
    baseURL,
    channel: process.env.HERMES_E2E_BROWSER_CHANNEL || undefined,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "off",
  },
  webServer: {
    command:
      `rm -rf .playwright-hermes-home && mkdir -p .playwright-hermes-home && ` +
      `HERMES_HOME=$PWD/.playwright-hermes-home PYTHONPATH=.. ` +
      `${process.env.PYTHON ?? "python3"} e2e/enterprise-server.py --port ${port}`,
    url: `${baseURL}/__e2e/health`,
    reuseExistingServer: !process.env.CI,
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
      name: "tablet-reduced-motion",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 768, height: 1024 },
      },
    },
    {
      name: "desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } },
    },
  ],
});
