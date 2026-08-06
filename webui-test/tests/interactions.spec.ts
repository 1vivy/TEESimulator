import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { donorStatus, installBridge } from "./fixtures";

test("keeps the skip link hidden until keyboard focus", async ({ page }) => {
  await installBridge(page);
  await page.goto("/");

  const skipLink = page.getByRole("link", { name: "Skip to controls" });
  await expect(skipLink).toHaveCSS("opacity", "0");
  await skipLink.focus();
  await expect(skipLink).toHaveCSS("opacity", "1");
  const evidence = process.env.RKA_WEBUI_EVIDENCE_DIR;
  if (evidence !== undefined) {
    await mkdir(evidence, { recursive: true });
    await skipLink.screenshot({ path: `${evidence}/task-26-skip-link-focused.png` });
    const bounds = await skipLink.boundingBox();
    if (bounds === null) throw new Error("focused skip link has no bounds");
    await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
    await page.mouse.down();
    await skipLink.screenshot({ path: `${evidence}/task-26-skip-link-active.png` });
    await page.mouse.up();
  }
  await skipLink.press("Enter");
  await expect(page).toHaveURL(/#main-content$/);
});

test("enables profile application only after validating the current file", async ({ page }) => {
  await installBridge(page);
  await page.goto("/");
  await expect(page.getByLabel("Last operation")).toHaveText("Status refreshed");
  await page.getByText("Advanced maintenance", { exact: true }).click();

  const validate = page.getByRole("button", { name: "Validate profile" });
  const apply = page.getByRole("button", { name: "Apply validated profile" });
  await page.locator("#profile-file").setInputFiles(
    resolve(import.meta.dirname, "../../tests/fixtures/profile-candidate.json"),
  );

  await expect(validate).toBeEnabled();
  await expect(apply).toBeDisabled();
  await validate.click();
  await expect(apply).toBeEnabled();

  await page.locator("#profile-file").setInputFiles({
    name: "donor.json",
    mimeType: "application/json",
    buffer: Buffer.from(
      JSON.stringify({ version: 1, role: "DONOR", profile_epoch: 0, transport: "DIRECT_NETWORK" }),
    ),
  });
  await expect(validate).toBeEnabled();
  await expect(apply).toBeDisabled();
});

test("shows immediate pending feedback while a privileged action is running", async ({ page }) => {
  let releaseStart = () => {};
  let startReached = false;
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui start ")) {
      await route.continue();
      return;
    }
    startReached = true;
    await new Promise<void>((resolve) => {
      releaseStart = resolve;
    });
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${donorStatus.replace("runtime=STOPPED", "runtime=RUNNING")}\nnext_nonce=${"b".repeat(32)}`,
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");
  await expect(page.getByLabel("Last operation")).toHaveText("Status refreshed");

  const start = page.locator('button[data-action="start"]');
  await expect(start).toHaveAccessibleName("Start runtime");
  await start.click();
  await expect.poll(() => startReached).toBe(true);
  await expect(start).toHaveText("Starting…");
  await expect(start).toHaveAttribute("aria-busy", "true");
  await expect(page.getByRole("button", { name: "Refresh status" })).toBeDisabled();
  await expect(page.getByRole("status")).toContainText("Starting runtime");

  releaseStart();
  await expect(start).toHaveAttribute("aria-busy", "false");
  await expect(page.getByRole("status")).toContainText("Runtime started");
  await expect(page.locator("#session-activity li")).toContainText(["Runtime started"]);
  await expect(page.locator("#session-activity li").first()).toHaveAttribute("data-health", "healthy");
});

test("surfaces fixed-control stderr instead of a generic failure", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui start ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 1,
        stderr: `RKA_DAEMON_FAILED child=SIDECAR token=${"f".repeat(32)}`,
        stdout: "WEBUI_INVALID_REQUEST\n",
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");
  await expect(page.getByLabel("Last operation")).toHaveText("Status refreshed");

  await page.locator('button[data-action="start"]').click();

  await expect(page.getByRole("status")).toContainText("RKA_DAEMON_FAILED child=SIDECAR");
  await expect(page.getByRole("status")).not.toContainText("f".repeat(32));
  await expect(page.locator('button[data-action="start"]')).toBeEnabled();
  await expect(page.locator("#session-activity li").first()).toHaveAttribute("data-health", "degraded");
});

test("keeps an indeterminate protected action outcome unknown", async ({ page }) => {
  test.setTimeout(45_000);
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui cleanup ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${donorStatus}\nconfirmation_action=cleanup\nconfirmation_token=${"a".repeat(32)}\nnext_nonce=${"b".repeat(32)}`,
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");
  await page.getByText("Advanced maintenance", { exact: true }).click();
  await page.getByRole("button", { name: "Clear runtime state" }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  const token = await page.locator("#confirmation-token").textContent();
  if (token === null) throw new TypeError("confirmation token was absent");

  await page.evaluate(() => {
    globalThis.ksu.exec = () => undefined;
  });
  await page.locator("#confirmation-input").fill(token);
  await page.getByRole("button", { name: "Confirm action" }).click();

  await expect(page.locator("#confirmation-state")).toHaveText(
    "Protected action outcome unknown · reopen this page",
    { timeout: 35_000 },
  );
  await expect(page.locator("#confirmation-heading")).toHaveText("Outcome unknown");
  await expect(page.locator("#confirmation-field")).toBeHidden();
  await expect(page.locator("#confirmation-cancel")).toBeHidden();
  await expect(page.getByLabel("Last operation")).toHaveText("Outcome unknown · reopen this page");
  await expect(page.getByRole("status")).toContainText("Outcome unknown");
  await expect(page.locator("#session-activity li").first()).toContainText("Unknown");
  await expect(page.locator("#session-activity li").first()).toHaveAttribute("data-health", "neutral");
  const evidence = process.env.RKA_WEBUI_EVIDENCE_DIR;
  if (evidence !== undefined) {
    await page.screenshot({ path: `${evidence}/task-26-confirm-unknown.png` });
  }
});

test("saves peer addresses with the fixed default port and keeps activity session-only", async ({
  page,
}) => {
  let saveCommand = "";
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui status ")) {
      await route.fulfill({
        body: JSON.stringify({ errno: 0, stdout: donorStatus }),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (command.includes(" webui network-save ")) {
      saveCommand = command;
      await route.fulfill({
        body: JSON.stringify({
          errno: 0,
          stdout: `${donorStatus.replace("100.64.0.2", "100.70.0.2")}\nnext_nonce=${"a".repeat(32)}`,
        }),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    await route.continue();
  });
  await installBridge(page);
  await page.goto("/");

  await expect(page.locator("#network-port")).toHaveValue("37373");
  await expect(page.locator("#network-port")).toHaveAttribute("readonly", "");
  await page.locator("#network-peer-ip").fill("100.70.0.2");
  await page.getByRole("button", { name: "Save network settings" }).click();

  await expect.poll(() => saveCommand).toContain(" network-save ");
  expect(saveCommand).toContain("100.70.0.2,100.64.0.1,37373");
  await expect(page.getByRole("status")).toContainText("Network settings saved");
  await expect(page.locator("#session-activity li")).toHaveCount(1);
  expect(await page.evaluate(() => localStorage.length + sessionStorage.length)).toBe(0);

  await page.reload();
  await expect(page.locator("#session-activity li")).toHaveCount(0);
});

test("rejects malformed IPv4 locally without invoking the privileged bridge", async ({ page }) => {
  let networkSaveCalls = 0;
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui network-save ")) {
      networkSaveCalls += 1;
    }
    await route.continue();
  });
  await installBridge(page);
  await page.goto("/");

  await page.locator("#network-peer-ip").fill("100.70.0.999");
  await page.getByRole("button", { name: "Save network settings" }).click();

  await expect(page.locator("#network-peer-error")).toContainText("valid IPv4");
  expect(networkSaveCalls).toBe(0);
});
