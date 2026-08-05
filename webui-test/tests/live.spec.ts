import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const evidence = resolve(
  process.env.RKA_WEBUI_EVIDENCE_DIR ??
    resolve(
      import.meta.dirname,
      "../../../TEESimulator-RS/.omo/evidence/two-device-rkp-rka-rust-runtime/round8/task-26-executor",
    ),
);

const candidateStatus = (candidate: string, readiness: "NOT_READY" | "READY") =>
  [
    `candidate_begin=${candidate}`,
    `candidate_id=${candidate}`,
    "role=CANDIDATE",
    "phone_role=PHONE_B_CANDIDATE",
    "profile_epoch=0",
    "direct_profile=DIRECT_NETWORK",
    `direct_readiness=${readiness}`,
    "pairing=PAIRED",
    "diagnostic=DIAGNOSTIC_ONLY",
    "runtime=RUNNING",
    "sentinel=LIVE",
    "rkp_provisioning=NOT_APPLICABLE",
    "synthetic_lease=NOT_READY",
    "lease_epoch=NOT_APPLICABLE",
    "lease_next=EMPTY",
    "lease_valid_until_millis=NOT_APPLICABLE",
    "quarantine_count=0",
    `candidate_end=${candidate}`,
  ].join("\n");

const installBridge = (page: Page) =>
  page.addInitScript(() => {
    globalThis.ksu = {
      exec: async (command: string, callback: string) => {
        const response = await fetch("/api/exec", {
          body: JSON.stringify({ command }),
          headers: { "content-type": "application/json" },
          method: "POST",
        });
        const result = await response.json();
        const callbackName = callback.slice(callback.lastIndexOf(".") + 1);
        globalThis.__teesimulatorRkaCallbacks[callbackName](
          result.errno,
          result.stdout,
          result.stderr ?? "",
        );
      },
    };
  });

test("rendersOneStatusCardPerPairedCandidateWithIndependentLeaseButtons", async ({ page }) => {
  let statusCalls = 0;
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui renew-synthetic-lease ")) {
      await route.fulfill({
        body: JSON.stringify({ errno: 1, stdout: "" }),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    statusCalls += 1;
    const candidateA = candidateStatus("candidate-a", statusCalls === 1 ? "NOT_READY" : "READY");
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${candidateA}\n${candidateStatus("candidate-b", "NOT_READY")}`,
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);

  await page.goto("/");
  const cards = page.locator(".candidate-status-card");
  await expect(cards).toHaveCount(2);
  await expect(cards.nth(0).getByRole("heading", { name: "candidate-a" })).toBeVisible();
  await expect(cards.nth(1).getByRole("heading", { name: "candidate-b" })).toBeVisible();
  const candidateA = cards.nth(0).getByRole("button", { name: "Issue / renew candidate lease" });
  const candidateB = cards.nth(1).getByRole("button", { name: "Issue / renew candidate lease" });
  await expect(candidateA).toBeDisabled();
  await expect(candidateB).toBeDisabled();

  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(candidateA).toBeEnabled();
  await expect(candidateB).toBeDisabled();
  const request = page.waitForRequest((value) =>
    (value.postData() ?? "").includes(" webui renew-synthetic-lease "),
  );
  await candidateA.click();
  await expect((await request).postData() ?? "").toContain(" --candidate candidate-a");
});

test("returnsFocusToTheTriggeringCandidateControlAfterTheDialogCloses", async ({ page }) => {
  const cards = `${candidateStatus("candidate-a", "READY")}\n${candidateStatus("candidate-b", "NOT_READY")}`;
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui renew-synthetic-lease ")) {
      await route.fulfill({
        body: JSON.stringify({ errno: 0, stdout: `${cards}\nconfirmation_token=abcdef` }),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({ errno: 0, stdout: cards }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);

  // Given: a ready candidate whose protected action opens the confirmation dialog.
  await page.goto("/");
  const statusCards = page.locator(".candidate-status-card");
  await expect(statusCards).toHaveCount(2);
  const candidateA = statusCards
    .nth(0)
    .getByRole("button", { name: "Issue / renew candidate lease" });
  await expect(candidateA).toBeEnabled();

  // When: the dialog is opened from that control and then closed.
  await candidateA.click();
  await expect(page.locator("#confirmation-dialog")).toHaveAttribute("open", "");
  await page.evaluate(() => {
    document.querySelector("#confirmation-dialog").close();
  });

  // Then: focus returns to that candidate's own live control, not to the document body.
  await expect
    .poll(() =>
      page.evaluate(() => {
        const active = document.activeElement;
        return active instanceof HTMLElement
          ? `${active.dataset.action ?? ""}:${active.dataset.candidateId ?? ""}`
          : "";
      }),
    )
    .toBe("renew-synthetic-lease:candidate-a");
});

test("keepsTwoCandidateCardsResponsiveWithCardMajorFocusOrder", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${candidateStatus("candidate-a", "READY")}\n${candidateStatus("candidate-b", "READY")}`,
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");
  const cards = page.locator(".candidate-status-card");

  await page.setViewportSize({ width: 1280, height: 900 });
  const wideA = await cards.nth(0).boundingBox();
  const wideB = await cards.nth(1).boundingBox();
  if (wideA === null || wideB === null || wideA.x + wideA.width > wideB.x || wideA.y !== wideB.y) {
    throw new Error("candidate status cards overlap or do not form a wide row");
  }

  await page.setViewportSize({ width: 375, height: 812 });
  const narrowA = await cards.nth(0).boundingBox();
  const narrowB = await cards.nth(1).boundingBox();
  if (narrowA === null || narrowB === null || narrowA.y + narrowA.height > narrowB.y) {
    throw new Error("candidate status cards overlap at narrow width");
  }
  const hasHorizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  );
  expect(hasHorizontalOverflow).toBe(false);

  const candidateA = cards.nth(0).getByRole("button", { name: "Issue / renew candidate lease" });
  const candidateB = cards.nth(1).getByRole("button", { name: "Issue / renew candidate lease" });
  await candidateA.focus();
  await page.keyboard.press("Tab");
  await expect(candidateB).toBeFocused();
  await expect(candidateB).toHaveCSS("outline-width", "3px");
});

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
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui start ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: [
          "role=DONOR",
          "phone_role=PHONE_A_DONOR",
          "profile_epoch=0",
          "direct_profile=DIRECT_NETWORK",
          "direct_readiness=READY",
          "pairing=PAIRED",
          "diagnostic=DIAGNOSTIC_ONLY",
          "runtime=RUNNING",
          "sentinel=LIVE",
          "rkp_provisioning=NOT_READY",
          "synthetic_lease=NOT_APPLICABLE",
          "lease_epoch=NOT_APPLICABLE",
          "lease_next=EMPTY",
          "lease_valid_until_millis=NOT_APPLICABLE",
          "quarantine_count=0",
        ].join("\n"),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
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
  const renewal = page.getByRole("button", { name: "Issue / renew candidate lease" });
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: [
          "role=CANDIDATE",
          "phone_role=PHONE_B_CANDIDATE",
          "profile_epoch=0",
          "direct_profile=DIRECT_NETWORK",
          "direct_readiness=READY",
          "pairing=PAIRED",
          "diagnostic=DIAGNOSTIC_ONLY",
          "runtime=RUNNING",
          "sentinel=LIVE",
          "rkp_provisioning=NOT_APPLICABLE",
          "synthetic_lease=NOT_READY",
          "lease_epoch=NOT_APPLICABLE",
          "lease_next=EMPTY",
          "lease_valid_until_millis=NOT_APPLICABLE",
          "quarantine_count=0",
        ].join("\n"),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Refresh status" }).click();
  await expect(renewal).toBeEnabled();

  const renewalToken = "0123456789abcdef0123456789abcdef";
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: [
          "confirmation_action=renew-synthetic-lease",
          `confirmation_token=${renewalToken}`,
          "role=CANDIDATE",
          "phone_role=PHONE_B_CANDIDATE",
          "profile_epoch=0",
          "direct_profile=DIRECT_NETWORK",
          "direct_readiness=READY",
          "pairing=PAIRED",
          "diagnostic=DIAGNOSTIC_ONLY",
          "runtime=RUNNING",
          "sentinel=LIVE",
          "rkp_provisioning=NOT_APPLICABLE",
          "synthetic_lease=NOT_READY",
          "lease_epoch=NOT_APPLICABLE",
          "lease_next=EMPTY",
          "lease_valid_until_millis=NOT_APPLICABLE",
          "quarantine_count=0",
        ].join("\n"),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await renewal.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.locator("#confirmation-state")).toHaveText("Awaiting one-time token");
  await page.screenshot({ path: `${evidence}/task-26-renew-awaiting.png` });
  await page.locator("#confirmation-input").fill(renewalToken);
  await page.route("/api/exec", async (route) => {
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: [
          "synthetic_lease_renewal=READY",
          "role=CANDIDATE",
          "phone_role=PHONE_B_CANDIDATE",
          "profile_epoch=0",
          "direct_profile=DIRECT_NETWORK",
          "direct_readiness=READY",
          "pairing=PAIRED",
          "diagnostic=DIAGNOSTIC_ONLY",
          "runtime=RUNNING",
          "sentinel=LIVE",
          "rkp_provisioning=NOT_APPLICABLE",
          "synthetic_lease=ACTIVE",
          "lease_epoch=0",
          "lease_next=EMPTY",
          "lease_valid_until_millis=1800000000000",
          "quarantine_count=0",
        ].join("\n"),
      }),
      contentType: "application/json",
      status: 200,
    });
  }, { times: 1 });
  await page.getByRole("button", { name: "Confirm action" }).click();
  await expect(page.locator("#confirmation-state")).toHaveText("Protected action accepted");
  await expect(page.getByText("Active", { exact: true })).toBeVisible();
  await expect(page.getByText("1,800,000,000,000", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: `${evidence}/task-26-renew-accepted.png` });
  await page.getByRole("button", { name: "Close" }).click();
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
