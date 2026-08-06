import { expect, test } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { installBridge, singleStatus } from "./fixtures";
import { captureResponsiveStates, exerciseCleanupConfirmations } from "./workflow-helpers";

const evidence = resolve(
  process.env.RKA_WEBUI_EVIDENCE_DIR ??
    resolve(
      import.meta.dirname,
      "../../../TEESimulator-RS/.omo/evidence/two-device-rkp-rka-rust-runtime/round8/task-26-executor",
    ),
);

test("live fixed controls expose stable accessible state", async ({ page }) => {
  await installBridge(page);
  await page.goto("/");
  await mkdir(evidence, { recursive: true });
  await expect(page.locator('[data-status-field="role"]').first()).toHaveText("Donor");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Request direct pairing" }).click(),
  ]);
  await expect(page.getByLabel("Last operation")).toHaveText("Request accepted");
  await page.getByRole("button", { name: "Start runtime" }).click();
  await expect(page.locator('[data-status-field="runtime"]').first()).toHaveText("Running");
  const provision = page.getByRole("button", { name: "Provision donor lease" });
  await expect(provision).toBeEnabled();
  const [provisionPreparation] = await Promise.all([
    page.waitForResponse((response) =>
      response.url().endsWith("/api/exec")
      && (response.request().postData() ?? "").includes(" webui provision-rkp "),
    ),
    provision.click(),
  ]);
  await expect(provisionPreparation.text()).resolves.toContain("confirmation_action=provision-rkp");
  await expect(page.getByRole("dialog")).toBeVisible();
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
  await page.screenshot({ path: `${evidence}/task-26-provisioned-donor.png`, fullPage: true });
  await page.getByRole("button", { name: "Stop runtime" }).click();

  await page.getByText("Advanced maintenance", { exact: true }).click();
  await page.locator("#profile-file").setInputFiles(
    resolve(import.meta.dirname, "../../tests/fixtures/profile-candidate.json"),
  );
  await expect(page.getByLabel("Last operation")).toHaveText("Profile loaded, not applied");
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Validate profile" }).click(),
  ]);
  await Promise.all([
    page.waitForResponse((response) => response.url().endsWith("/api/exec")),
    page.getByRole("button", { name: "Apply validated profile" }).click(),
  ]);
  await expect(page.locator('[data-status-field="role"]').first()).toHaveText("Candidate");
  await expect(provision).toBeDisabled();
  const renewal = page.getByRole("button", { name: "Issue / renew candidate lease" });
  await page.getByRole("button", { name: "Start runtime" }).click();
  await expect(renewal).toBeEnabled();

  const [renewalPreparation] = await Promise.all([
    page.waitForResponse((response) =>
      response.url().endsWith("/api/exec")
      && (response.request().postData() ?? "").includes(" webui renew-synthetic-lease "),
    ),
    renewal.click(),
  ]);
  await expect(renewalPreparation.text()).resolves.toContain(
    "confirmation_action=renew-synthetic-lease",
  );
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-renew-awaiting.png` });
  const renewalToken = await page.locator("#confirmation-token").textContent();
  if (renewalToken === null) throw new Error("renewal confirmation token was absent");
  await page.locator("#confirmation-input").fill(renewalToken);
  await page.route("/api/exec", async (route) => {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 400));
    await route.continue();
  }, { times: 1 });
  const renewalResponse = page.waitForResponse((response) => response.url().endsWith("/api/exec"));
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(page.locator("#confirmation-state")).toHaveText("Applying protected action");
  await page.screenshot({ path: `${evidence}/task-26-renew-busy.png` });
  await renewalResponse;
  await expect(page.locator("#confirmation-state")).toHaveText("Protected action accepted");
  await expect(page.getByText("Active", { exact: true })).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-renew-accepted.png` });
  await page.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: "Stop runtime" }).click();

  await captureResponsiveStates(page, evidence, provision);
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: singleStatus({
          role: "LOCAL", phoneRole: "LOCAL_LEGACY", readiness: "NOT_READY",
          runtime: "QUARANTINED_AMBIGUOUS_MUTATION", sentinel: "NOT_READY",
          provisioning: "NOT_APPLICABLE", lease: "NOT_APPLICABLE",
          leaseEpoch: "NOT_APPLICABLE", leaseValidUntil: "NOT_APPLICABLE",
          quarantineCount: 1,
        }),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(page.locator('[data-status-field="role"]').first()).toHaveText("Local");
  await expect(page.getByText("Local · legacy", { exact: true })).toBeVisible();
  await expect(page.getByText("Quarantined · ambiguous mutation", { exact: true })).toBeVisible();
  await page.screenshot({ path: `${evidence}/task-26-failure-state.png`, fullPage: true });
  await exerciseCleanupConfirmations(page, evidence);
});
