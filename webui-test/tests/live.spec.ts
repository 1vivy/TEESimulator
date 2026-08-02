import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const evidence = resolve(
  process.env.RKA_WEBUI_EVIDENCE_DIR ??
    resolve(
      import.meta.dirname,
      "../../../TEESimulator-RS/.omo/evidence/two-device-rkp-rka-rust-runtime/round8/task-26-executor",
    ),
);

test("live fixed controls expose stable accessible state", async ({ page }) => {
  await page.addInitScript(() => {
    globalThis.ksu = {
      exec: async (command: string) => {
        const response = await fetch("/api/exec", {
          body: JSON.stringify({ command }),
          headers: { "content-type": "application/json" },
          method: "POST",
        });
        return response.json();
      },
    };
  });
  await page.goto("/");
  await mkdir(evidence, { recursive: true });
  await expect(page.getByLabel("rka-role-value")).toHaveText("Donor");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Request direct pairing" }).click(),
  ]);
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Request accepted");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByLabel("rka-start").click(),
  ]);
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Request accepted");
  await expect(page.getByLabel("rka-connection-value")).toHaveText("Ready");

  const provision = page.getByRole("button", { name: "Provision donor lease" });
  await provision.click();
  const provisionDialog = page.getByRole("dialog");
  await expect(provisionDialog).toBeVisible();
  await expect(page.locator("#confirmation-state")).toHaveText("Awaiting one-time token");
  await page.screenshot({ path: `${evidence}/task-26-provision-awaiting.png` });
  const provisionToken = await page.locator("#confirmation-token").textContent();
  if (provisionToken === null) throw new Error("provision confirmation token was absent");
  await page.locator("#confirmation-input").fill(provisionToken);
  await page.route("/api/exec", async (route) => {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 400));
    await route.continue();
  }, { times: 1 });
  const provisionResponse = page.waitForResponse((response) => response.url().endsWith("/api/exec"));
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(page.locator("#confirmation-state")).toHaveText("Applying protected action");
  await page.screenshot({ path: `${evidence}/task-26-provision-busy.png` });
  await provisionResponse;
  await expect(page.locator("#confirmation-state")).toHaveText("Protected action accepted");
  await expect(page.getByText("Provisioned", { exact: true })).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-provision-accepted.png` });
  await page.getByRole("button", { name: "Close" }).click();
  await expect(page.getByLabel("rka-role-value")).toHaveText("Donor");
  await expect(page.getByText("Provisioned", { exact: true })).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-provisioned-donor.png`, fullPage: true });
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByLabel("rka-stop").click(),
  ]);
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Request accepted");

  await page.locator("#profile-file").setInputFiles(
    resolve(import.meta.dirname, "../../tests/fixtures/profile-candidate.json"),
  );
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Profile loaded, not applied");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Validate profile" }).click(),
  ]);
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Request accepted");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Apply validated profile" }).click(),
  ]);
  await expect(page.getByLabel("rka-last-operation")).toHaveText("Request accepted");
  await expect(page.getByLabel("rka-role-value")).toHaveText("Candidate");
  await expect(page.getByLabel("rka-start")).toBeVisible();
  await expect(page.getByLabel("rka-stop")).toBeVisible();
  await expect(provision).toBeDisabled();
  const profileTarget = await page.locator("#profile-file").boundingBox();
  if (profileTarget === null || profileTarget.height < 44) {
    throw new Error("profile file target is smaller than 44px");
  }
  for (const [width, height] of [[375, 812], [768, 1024], [1280, 900]] as const) {
    await page.setViewportSize({ width, height });
    await expect(page.getByLabel("rka-start")).toBeEnabled();
    await expect(page.getByLabel("rka-stop")).toBeEnabled();
    await expect(provision).toBeDisabled();
    const provisionTarget = await provision.boundingBox();
    if (provisionTarget === null || provisionTarget.height < 44) {
      throw new Error("provision control is smaller than 44px");
    }
    await page.evaluate(() => new Promise<void>((done) => requestAnimationFrame(() => requestAnimationFrame(() => done()))));
    await page.screenshot({ path: `${evidence}/task-26-webui-${width}.png`, fullPage: true });
  }
  const stop = page.getByLabel("rka-stop");
  await stop.hover();
  await page.screenshot({ path: `${evidence}/task-26-webui-hover.png`, fullPage: true });
  await page.getByLabel("rka-start").focus();
  await page.keyboard.press("Tab");
  await expect(stop).toBeFocused();
  await expect(stop).toHaveCSS("outline-width", "3px");
  await page.screenshot({ path: `${evidence}/task-26-webui-focus.png`, fullPage: true });
  const bounds = await stop.boundingBox();
  if (bounds === null) throw new Error("stop control has no bounds");
  await page.mouse.move(bounds.x + bounds.width / 2, bounds.y + bounds.height / 2);
  await page.mouse.down();
  await page.screenshot({ path: `${evidence}/task-26-webui-active.png`, fullPage: true });
  await page.mouse.move(0, 0);
  await page.mouse.up();

  const dialog = page.getByRole("dialog");
  const confirmationState = page.locator("#confirmation-state");
  await page.getByRole("button", { name: "Clear runtime state" }).click();
  await expect(dialog).toBeVisible();
  await expect(confirmationState).toHaveText("Awaiting one-time token");
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
  await expect(page.getByRole("button", { name: "Confirm action" })).toBeDisabled();
  await page.screenshot({ path: `${evidence}/task-26-confirm-busy.png` });
  await acceptedResponse;
  await expect(confirmationState).toHaveText("Protected action accepted");
  await page.screenshot({ path: `${evidence}/task-26-confirm-accepted.png` });
  await page.getByRole("button", { name: "Close" }).click();

  await page.getByRole("button", { name: "Clear runtime state" }).click();
  await expect(dialog).toBeVisible();
  await expect(confirmationState).toHaveText("Awaiting one-time token");
  await expect(page.locator("#confirmation-token")).not.toHaveText(confirmationToken);
  const refusedToken = await page.locator("#confirmation-token").textContent();
  if (refusedToken === null) throw new Error("refused token was absent");
  await page.locator("#confirmation-input").fill(refusedToken);
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({ errno: 1, stdout: "" }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(confirmationState).toHaveText("Protected action refused");
  await page.screenshot({ path: `${evidence}/task-26-confirm-refused.png` });
  await page.getByRole("button", { name: "Close" }).click();

  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: [
          "role=LOCAL",
          "phone_role=LOCAL_LEGACY",
          "profile_epoch=0",
          "direct_profile=UNAVAILABLE",
          "direct_readiness=NOT_READY",
          "pairing=UNPAIRED",
          "diagnostic=DIAGNOSTIC_ONLY",
          "runtime=QUARANTINED_AMBIGUOUS_MUTATION",
          "sentinel=NOT_READY",
          "quarantine_count=1",
        ].join("\n"),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.getByLabel("rka-role-value")).toHaveText("Local");
  await expect(page.getByText("Local · legacy", { exact: true })).toBeVisible();
  await expect(page.getByText("Quarantined · ambiguous mutation", { exact: true })).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-failure-state.png`, fullPage: true });
});
