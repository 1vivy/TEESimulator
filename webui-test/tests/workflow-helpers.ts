import { expect } from "@playwright/test";
import type { Locator, Page } from "@playwright/test";

export const captureResponsiveStates = async (
  page: Page,
  evidence: string,
  provision: Locator,
): Promise<void> => {
  const profileTarget = await page.locator("#profile-file").boundingBox();
  if (profileTarget === null || profileTarget.height < 44) {
    throw new Error("profile file target is smaller than 44px");
  }
  for (const [width, height] of [[375, 812], [768, 1024], [1280, 900]] as const) {
    await page.setViewportSize({ width, height });
    await expect(page.getByRole("button", { name: "Start runtime" })).toBeEnabled();
    await expect(page.getByRole("button", { name: "Stop runtime" })).toBeEnabled();
    await expect(provision).toBeDisabled();
    const provisionTarget = await provision.boundingBox();
    if (provisionTarget === null || provisionTarget.height < 44) {
      throw new Error("provision control is smaller than 44px");
    }
    await page.evaluate(() => new Promise<void>((done) =>
      requestAnimationFrame(() => requestAnimationFrame(() => done())),
    ));
    await page.screenshot({ path: `${evidence}/task-26-webui-${width}.png`, fullPage: true });
  }
  const stop = page.getByRole("button", { name: "Stop runtime" });
  await stop.hover();
  await stop.screenshot({ path: `${evidence}/task-26-webui-hover.png` });
  await page.getByRole("button", { name: "Start runtime" }).focus();
  await page.keyboard.press("Tab");
  await expect(stop).toBeFocused();
  await expect(stop).toHaveCSS("outline-width", "3px");
  await stop.screenshot({ path: `${evidence}/task-26-webui-focus.png` });
  const bounds = await stop.boundingBox();
  if (bounds === null) throw new Error("stop control has no bounds");
  await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
  await page.mouse.down();
  await stop.screenshot({ path: `${evidence}/task-26-webui-active.png` });
  await page.mouse.move(0, 0);
  await page.mouse.up();
};

export const exerciseCleanupConfirmations = async (
  page: Page,
  evidence: string,
): Promise<void> => {
  const dialog = page.getByRole("dialog");
  const confirmationState = page.locator("#confirmation-state");
  await page.getByRole("button", { name: "Clear runtime state" }).click();
  await expect(dialog).toBeVisible();
  await expect(confirmationState).toHaveText("Awaiting one-time token");
  await expect(page.locator("#confirmation-instructions")).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-confirm-awaiting.png` });

  await page.locator("#confirmation-input").fill("not-the-token");
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(confirmationState).toHaveText("Token mismatch · request not sent");
  await page.screenshot({ path: `${evidence}/task-26-confirm-mismatch.png` });

  const confirmationToken = await page.locator("#confirmation-token").textContent();
  if (confirmationToken === null) throw new Error("confirmation token was absent");
  await page.locator("#confirmation-input").fill(confirmationToken);
  await page.route("/api/exec", async (route) => {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 400));
    await route.continue();
  }, { times: 1 });
  const acceptedResponse = page.waitForResponse((response) => response.url().endsWith("/api/exec"));
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(confirmationState).toHaveText("Applying protected action");
  await expect(page.locator("#confirmation-submit")).toBeDisabled();
  await page.screenshot({ path: `${evidence}/task-26-confirm-busy.png` });
  await acceptedResponse;
  await expect(confirmationState).toHaveText("Protected action accepted");
  await expect(page.locator("#confirmation-instructions")).toBeHidden();
  await expect(page.locator("#confirmation-field")).toBeHidden();
  await expect(page.locator("#confirmation-cancel")).toBeHidden();
  await expect(page.locator("#confirmation-heading")).toHaveText("Action accepted");
  await page.screenshot({ path: `${evidence}/task-26-confirm-accepted.png` });
  await page.getByRole("button", { name: "Close" }).click();

  await page.getByRole("button", { name: "Clear runtime state" }).click();
  await expect(dialog).toBeVisible();
  await expect(confirmationState).toHaveText("Awaiting one-time token");
  await expect(page.locator("#confirmation-token")).not.toHaveText(confirmationToken);
  const indeterminateToken = await page.locator("#confirmation-token").textContent();
  if (indeterminateToken === null) throw new Error("indeterminate token was absent");
  await page.locator("#confirmation-input").fill(indeterminateToken);
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({ errno: 1, stdout: "" }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(confirmationState).toHaveText("Protected action outcome unknown · reopen this page");
  await expect(page.locator("#confirmation-instructions")).toBeHidden();
  await expect(page.locator("#confirmation-field")).toBeHidden();
  await expect(page.locator("#confirmation-cancel")).toBeHidden();
  await expect(page.locator("#confirmation-heading")).toHaveText("Outcome unknown");
  await expect(page.locator("#session-activity li").first()).toHaveAttribute("data-health", "neutral");
  await expect(page.locator("#session-activity li").first()).toContainText("Unknown");
  await page.screenshot({ path: `${evidence}/task-26-confirm-indeterminate.png` });
  await page.getByRole("button", { name: "Close" }).click();
};
