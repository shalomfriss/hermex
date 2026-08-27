import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

const USERNAME = "operator@example.test";
const PASSWORD = "correct horse battery staple";

async function setMode(page: Page, mode: "ok" | "denied" | "outage" | "expired") {
  const response = await page.request.post(`/__e2e/mode?value=${mode}`);
  expect(response.ok()).toBeTruthy();
}

async function login(page: Page, target = "/sessions", prefix = "") {
  await setMode(page, "ok");
  await page.goto(`${prefix}${target}`);
  await expect(page).toHaveURL(new RegExp(`${prefix}/login\\?next=`));
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password").fill(PASSWORD);
  await Promise.all([
    page.waitForURL((url) => url.pathname === `${prefix}${target.split(/[?#]/)[0]}`),
    page.getByRole("button", { name: /sign in/i }).click(),
  ]);
}

async function expectNoSeriousAxeViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .exclude(".xterm")
    .analyze();
  const blocking = results.violations.filter(
    (violation) => violation.impact === "critical" || violation.impact === "serious",
  );
  expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
}

async function navigateToSystemWithKeyboard(page: Page) {
  let reachedSystemLink = false;
  for (let index = 0; index < 40; index += 1) {
    await page.keyboard.press("Tab");
    const focused = await page.evaluate(() => {
      const element = document.activeElement;
      return {
        href: element?.getAttribute("href") ?? "",
        label: element?.getAttribute("aria-label") ?? element?.textContent?.trim() ?? "",
      };
    });
    if (/open navigation/i.test(focused.label)) {
      await page.keyboard.press("Enter");
      continue;
    }
    if (focused.href === "/system") {
      reachedSystemLink = true;
      await page.keyboard.press("Enter");
      break;
    }
  }
  expect(reachedSystemLink).toBe(true);
  await expect(page).toHaveURL(/\/system$/);
}

test.beforeEach(async ({ page }) => {
  await setMode(page, "ok");
});

test.afterEach(async ({ page }) => {
  await setMode(page, "ok");
});

test("logged-out login is keyboard accessible, motion-safe, and serves production assets", async ({
  page,
}) => {
  const badResponses: string[] = [];
  page.on("response", (response) => {
    if (response.status() >= 400) badResponses.push(`${response.status()} ${response.url()}`);
  });

  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/sessions?owner=me#recent");
  await expect(page).toHaveURL(/\/login\?next=/);
  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
  expect(await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches)).toBe(
    true,
  );

  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Username")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Password")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeFocused();

  const assetUrls = await page.evaluate(() =>
    performance
      .getEntriesByType("resource")
      .map((entry) => entry.name)
      .filter((url) => /\.(?:js|css|woff2?|ico)(?:\?|$)/.test(url)),
  );
  expect(assetUrls.length).toBeGreaterThan(0);
  expect(badResponses).toEqual([]);
  await expectNoSeriousAxeViolations(page);
});

test("authentication restores deep links and responsive operator workflows", async ({
  page,
}, testInfo) => {
  await login(page, "/sessions?owner=me#recent");
  await expect(page).toHaveURL(/\/sessions\?owner=me$/);
  await expect(page.getByText("Enterprise Operator")).toBeVisible();

  const me = await page.request.get("/api/auth/me");
  expect(me.status()).toBe(200);
  expect((await me.json()).email).toBe(USERNAME);

  const dimensions = await page.evaluate(() => ({
    viewport: document.documentElement.clientWidth,
    scroll: document.documentElement.scrollWidth,
  }));
  expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.viewport + 1);

  if (testInfo.project.name === "desktop") {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Emulation.setPageScaleFactor", { pageScaleFactor: 2 });
    expect(
      await page.evaluate(() => ({
        scale: visualViewport?.scale ?? 1,
        overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      })),
    ).toMatchObject({ scale: 2, overflow: 0 });
  }

  await navigateToSystemWithKeyboard(page);
  await expect(page.getByRole("heading", { name: /system/i })).toBeVisible();
  await expectNoSeriousAxeViolations(page);
});

test("path-prefixed login restores routes and keeps assets and APIs under the prefix", async ({
  page,
}) => {
  const resources: string[] = [];
  page.on("response", (response) => {
    if (response.request().resourceType() !== "document") resources.push(response.url());
  });

  await login(page, "/system?tab=health#gateway", "/hermes");
  await expect(page).toHaveURL(/\/hermes\/system\?tab=health$/);
  await expect(page.getByRole("heading", { name: /system/i })).toBeVisible();
  expect(resources.filter((url) => /\.(?:js|css|woff2?)(?:\?|$)/.test(url))).not.toEqual([]);
  const unprefixedAssets = resources
    .filter((url) => /\.(?:js|css|woff2?)(?:\?|$)/.test(url))
    .filter((url) => !new URL(url).pathname.startsWith("/hermes/"));
  expect(unprefixedAssets, unprefixedAssets.join("\n")).toEqual([]);
  expect((await page.request.get("/hermes/api/auth/me")).status()).toBe(200);
});

test("authorization denial, provider outage, expiry, and logout fail safely", async ({ page }) => {
  await login(page);

  await setMode(page, "denied");
  await expect(page.getByRole("heading", { name: "Access denied" })).toBeVisible();
  await expect(page.getByRole("button", { name: /retry/i })).toHaveCount(0);

  await page.context().clearCookies();
  await login(page);
  await setMode(page, "outage");
  await expect(page.getByText("Sign-in provider unavailable")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();

  await page.context().clearCookies();
  await login(page, "/system?from=expiry");
  await setMode(page, "expired");
  await expect(page).toHaveURL(/\/login\?next=/);
  await setMode(page, "ok");
  await page.context().clearCookies();
  await page.getByLabel("Username").fill(USERNAME);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByLabel("Password").press("Enter");
  await expect(page).toHaveURL(/\/system\?from=expiry$/);

  const openNavigation = page.getByRole("button", { name: /open navigation/i });
  if (await openNavigation.isVisible()) {
    await openNavigation.focus();
    await page.keyboard.press("Enter");
  }
  await page.getByRole("button", { name: "Log out" }).focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/login/);
  expect((await (await page.request.get("/__e2e/state")).json()).logout_count).toBeGreaterThan(0);
  expect((await page.request.get("/api/auth/me")).status()).toBe(401);
});

test("WebSocket upgrades reject anonymous clients and accept fresh reconnect tickets", async ({
  page,
}) => {
  await page.goto("/login");
  const anonymousCode = await page.evaluate(
    () =>
      new Promise<number>((resolve) => {
        const socket = new WebSocket(`ws://${location.host}/api/events?channel=acceptance`);
        socket.onclose = (event) => resolve(event.code);
        socket.onerror = () => undefined;
      }),
  );
  // Browsers surface a pre-accept HTTP rejection as abnormal close 1006;
  // an accepted socket closed by the app would expose its application code.
  expect(anonymousCode).toBe(1006);

  await login(page);
  const opened = await page.evaluate(async () => {
    async function connect(): Promise<WebSocket> {
      const response = await fetch("/api/auth/ws-ticket", { method: "POST" });
      const { ticket } = await response.json();
      return await new Promise<WebSocket>((resolve, reject) => {
        const socket = new WebSocket(
          `ws://${location.host}/api/events?channel=acceptance&ticket=${encodeURIComponent(ticket)}`,
        );
        socket.onopen = () => resolve(socket);
        socket.onerror = () => reject(new Error("websocket failed"));
      });
    }
    const first = await connect();
    first.close();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const second = await connect();
    second.close();
    return 2;
  });
  expect(opened).toBe(2);
});
