import AxeBuilder from "@axe-core/playwright";
import { expect, type Page, test } from "@playwright/test";

async function openBoard(page: Page) {
  await page.goto("/kanban");
  await expect(page.locator("[data-task-id]").first()).toBeVisible();
}

async function expectNoBlockingAxeViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const blocking = results.violations.filter(
    (violation) => violation.impact === "critical" || violation.impact === "serious",
  );
  expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
}

test("board filters and cards expose a non-nested keyboard model", async ({ page }) => {
  await openBoard(page);

  await expect(page.getByRole("combobox", { name: "Switch kanban board" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Filter by tenant" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Filter by assignee" })).toBeVisible();

  const card = page.getByRole("group", { name: /task accessible task card 1 —/i });
  await expect(card).toHaveAttribute("role", "group");
  const openButton = card.getByRole("button", { name: /open task accessible task card 1/i });
  await expect(openButton).toBeVisible();
  await expect(card.getByRole("checkbox", { name: /select task/i })).toBeVisible();

  const nestedInteractive = await card.evaluate((element) => {
    const interactive = Array.from(
      element.querySelectorAll("button, a[href], input, select, textarea, [role='button']"),
    );
    return interactive.some((candidate) =>
      interactive.some((ancestor) => ancestor !== candidate && ancestor.contains(candidate)),
    );
  });
  expect(nestedInteractive).toBe(false);
});

test("keyboard opens a discoverable drawer and reaches scoped history controls", async ({ page }) => {
  await openBoard(page);

  const openButton = page
    .getByRole("group", { name: /task accessible task card 1 —/i })
    .getByRole("button", { name: /open task accessible task card 1 —/i });
  await openButton.focus();
  await page.keyboard.press("Enter");

  const drawer = page.getByRole("dialog", { name: /task details: accessible task card 1/i });
  await expect(drawer).toBeVisible();
  await expect(drawer.getByRole("button", { name: /close task details/i })).toBeFocused();
  await expect(drawer.getByRole("region", { name: /worker log for task/i })).toBeVisible();
  await expect(drawer.getByRole("button", { name: /refresh worker log for task/i })).toBeVisible();
  await expect(drawer.getByRole("region", { name: /run history for task/i })).toBeVisible();
  await expect(drawer.getByRole("button", { name: /show all run attempts for task/i })).toBeVisible();

  await page.keyboard.press("Shift+Tab");
  expect(await drawer.evaluate((element) => element.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Tab");
  await expect(drawer.getByRole("button", { name: /close task details/i })).toBeFocused();

  await page.keyboard.press("Escape");
  await expect(drawer).toHaveCount(0);
  await expect(openButton).toBeFocused();
});

test("card pointer open and native drag payload remain intact", async ({ page }) => {
  await openBoard(page);

  const card = page.getByRole("group", { name: /task accessible task card 1 —/i });
  const openButton = card.getByRole("button", { name: /open task accessible task card 1 —/i });
  const taskId = await card.getAttribute("data-task-id");

  await openButton.click();
  await expect(page.getByRole("dialog", { name: /task details: accessible task card 1/i })).toBeVisible();
  await page.getByRole("button", { name: /close task details/i }).click();

  await card.evaluate(() => {
    window.addEventListener("dragstart", (event) => {
      const dragEvent = event as DragEvent;
      (window as unknown as { __kanbanDragPayload?: string }).__kanbanDragPayload =
        dragEvent.dataTransfer?.getData("text/x-hermes-task") ?? "";
    }, { once: true });
  });
  const box = await openButton.boundingBox();
  expect(box).not.toBeNull();
  await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2);
  await page.mouse.down();
  await page.mouse.move(box!.x + box!.width / 2 + 30, box!.y + box!.height / 2 + 30, {
    steps: 5,
  });
  await page.mouse.up();
  expect(
    await page.evaluate(
      () => (window as unknown as { __kanbanDragPayload?: string }).__kanbanDragPayload,
    ),
  ).toBe(taskId);
});

test("production Kanban bundle has no critical or serious axe violations", async ({ page }) => {
  const scripts: string[] = [];
  page.on("response", (response) => {
    if (response.request().resourceType() === "script") scripts.push(response.url());
  });
  await openBoard(page);
  expect(scripts.some((url) => /\/assets\/.+\.js(?:\?|$)/.test(url))).toBe(true);
  await expectNoBlockingAxeViolations(page);
});
