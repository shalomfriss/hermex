import base from "./playwright.config";
import { defineConfig } from "@playwright/test";

export default defineConfig({
  ...base,
  testMatch: "integration-remediations.spec.ts",
  reporter: "list",
  outputDir: "test-results/integration-remediations",
});
