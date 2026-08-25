import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

const routes = [
  "/cron",
  "/skills",
  "/plugins",
  "/config",
  "/env",
  "/models",
  "/profiles",
  "/logs",
];

async function login(page: Page) {
  await page.request.post("/__e2e/mode?value=ok");
  await page.goto("/sessions");
  await page.getByLabel("Username").fill("operator@example.test");
  await page.getByLabel("Password").fill("correct horse battery staple");
  await Promise.all([
    page.waitForURL((url) => url.pathname === "/sessions"),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);
}

test("all remediated routes are production-bundle accessible and error-free", async ({ page, context }) => {
  test.setTimeout(120_000);
  await login(page);
  for (const route of routes) {
    const routePage = await context.newPage();
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    const failedRequests: string[] = [];
    const badResponses: string[] = [];
    routePage.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    });
    routePage.on("pageerror", (error) => pageErrors.push(error.message));
    routePage.on("requestfailed", (request) => {
      failedRequests.push(`${request.method()} ${request.url()} ${request.failure()?.errorText ?? ""}`);
    });
    routePage.on("response", (response) => {
      if (response.status() >= 400) badResponses.push(`${response.status()} ${response.url()}`);
    });

    await routePage.goto(route);
    await expect(routePage.locator("main")).toBeVisible();
    await routePage.waitForTimeout(500);
    const results = await new AxeBuilder({ page: routePage })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .exclude(".xterm")
      .analyze();
    const blocking = results.violations.filter(
      (violation) => violation.impact === "critical" || violation.impact === "serious",
    );
    expect(blocking, `${route}: ${JSON.stringify(blocking, null, 2)}`).toEqual([]);
    expect(consoleErrors, `${route} console errors`).toEqual([]);
    expect(pageErrors, `${route} page errors`).toEqual([]);
    expect(failedRequests, `${route} request failures`).toEqual([]);
    expect(badResponses, `${route} bad responses`).toEqual([]);
    await routePage.close();
  }
});

test("self-hosted docs render without external resources or runtime failures", async ({ page, context }) => {
  await login(page);
  const expectedOrigin = new URL(page.url()).origin;
  const docsPage = await context.newPage();
  const runtimeErrors: string[] = [];
  const externalResources: string[] = [];
  docsPage.on("console", (message) => {
    if (message.type() === "error") runtimeErrors.push(`console: ${message.text()}`);
  });
  docsPage.on("pageerror", (error) => runtimeErrors.push(`page: ${error.message}`));
  docsPage.on("requestfailed", (request) => runtimeErrors.push(`request: ${request.url()}`));
  docsPage.on("response", (response) => {
    if (response.status() >= 400) runtimeErrors.push(`response ${response.status()}: ${response.url()}`);
    if (new URL(response.url()).origin !== expectedOrigin) externalResources.push(response.url());
  });

  await docsPage.goto("/docs");
  await expect(docsPage.locator(".swagger-ui")).toBeVisible();
  await expect(docsPage.locator("html")).toHaveAttribute("lang", "en");
  expect(runtimeErrors).toEqual([]);
  expect(externalResources).toEqual([]);
});
