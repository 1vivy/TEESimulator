import { expect, test } from "@playwright/test";
import { donorCandidateStatus, installBridge, singleStatus } from "./fixtures";

test("marks met attestation prerequisites healthy and metadata neutral", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: singleStatus({
          role: "CANDIDATE", phoneRole: "PHONE_B_CANDIDATE", readiness: "READY",
          runtime: "RUNNING", sentinel: "LIVE", provisioning: "NOT_APPLICABLE",
          lease: "ACTIVE", leaseEpoch: "0", leaseValidUntil: "1800000000000",
        }),
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");

  const card = page.locator(".candidate-status-card");
  await expect(card.locator('[data-status-field="role"]')).toHaveAttribute("data-health", "neutral");
  await expect(card.locator('[data-status-field="runtime"]')).toHaveAttribute("data-health", "healthy");
  await expect(card.locator('[data-status-field="direct_readiness"]')).toHaveAttribute("data-health", "healthy");
  await expect(card.locator('[data-status-field="synthetic_lease"]')).toHaveAttribute("data-health", "healthy");
  await expect(card.locator('[data-status-field="lease_valid_until_millis"]')).toHaveAttribute("data-health", "healthy");
  await expect(card.locator('[data-status-field="lease_next"]')).toHaveAttribute("data-health", "neutral");
  await expect(card.locator('[data-status-field="quarantine_count"]')).toHaveAttribute("data-health", "healthy");
});

test("marks an unrepresentable lease timestamp unavailable and degraded", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: singleStatus({
          role: "CANDIDATE", phoneRole: "PHONE_B_CANDIDATE", readiness: "READY",
          runtime: "RUNNING", sentinel: "LIVE", provisioning: "NOT_APPLICABLE",
          lease: "ACTIVE", leaseEpoch: "0", leaseValidUntil: "9999999999999999",
        }),
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");

  const expiry = page.locator('[data-status-field="lease_valid_until_millis"]');
  await expect(expiry).toHaveText("Unavailable");
  await expect(expiry).toHaveAttribute("data-health", "degraded");
});

test("marks blocked and expired attestation prerequisites degraded", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: singleStatus({
          role: "CANDIDATE", phoneRole: "PHONE_B_CANDIDATE", readiness: "NOT_READY",
          runtime: "QUARANTINED_AMBIGUOUS_MUTATION", sentinel: "NOT_READY",
          provisioning: "NOT_APPLICABLE", lease: "ACTIVE", leaseEpoch: "0",
          leaseValidUntil: "1", quarantineCount: 1,
        }),
      }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);
  await page.goto("/");

  const card = page.locator(".candidate-status-card");
  await expect(card.locator('[data-status-field="runtime"]')).toHaveAttribute("data-health", "degraded");
  await expect(card.locator('[data-status-field="direct_readiness"]')).toHaveAttribute("data-health", "degraded");
  await expect(card.locator('[data-status-field="sentinel"]')).toHaveAttribute("data-health", "degraded");
  await expect(card.locator('[data-status-field="lease_valid_until_millis"]')).toHaveAttribute("data-health", "degraded");
  await expect(card.locator('[data-status-field="quarantine_count"]')).toHaveAttribute("data-health", "degraded");
});

test("renders production donor candidate blocks without unreachable lease controls", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui provision-rkp ")) {
      expect(command).toContain(" --candidate candidate-a");
      await route.fulfill({
        body: JSON.stringify({
          errno: 0,
          stdout: `${donorCandidateStatus("candidate-a", "READY")}\n${donorCandidateStatus("candidate-b", "NOT_READY")}\nconfirmation_action=provision-rkp\nconfirmation_token=${"a".repeat(32)}\nnext_nonce=${"b".repeat(32)}`,
        }),
        contentType: "application/json",
        status: 200,
      });
      return;
    }
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    const candidateA = donorCandidateStatus("candidate-a", "READY");
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${candidateA}\n${donorCandidateStatus("candidate-b", "NOT_READY")}`,
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
  await expect(cards.nth(0).locator('[data-status-field="runtime"]')).toHaveText("Running");
  await expect(cards.nth(1).locator('[data-status-field="runtime"]')).toHaveText("Stopped");
  await expect(cards.nth(0).locator('[data-status-field="lease_next"]')).toHaveAttribute("data-health", "neutral");
  await expect(cards.getByRole("button", { name: "Issue / renew candidate lease" })).toHaveCount(0);
  const candidateAProvision = page.getByRole("button", { name: "Provision candidate RKP for candidate-a" });
  await expect(candidateAProvision).toBeEnabled();
  await expect(page.getByRole("button", { name: "Provision candidate RKP for candidate-b" })).toBeDisabled();
  const evidence = process.env.RKA_WEBUI_EVIDENCE_DIR;
  if (evidence !== undefined) {
    await page.screenshot({ path: `${evidence}/task-26-two-candidates-mixed-readiness.png`, fullPage: true });
  }
  await candidateAProvision.click();
  await expect(page.locator("#confirmation-state")).toHaveText("Awaiting one-time token");
  await page.getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator("#network-peer-ip")).toBeDisabled();
  await expect(page.locator("#network-local-ip")).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save network settings" })).toBeDisabled();
  await expect(page.locator("#network-scope-message")).toContainText("host CLI");
});

test("returns focus to the local candidate lease control after dialog close", async ({ page }) => {
  const status = singleStatus({
    role: "CANDIDATE", phoneRole: "PHONE_B_CANDIDATE", readiness: "READY",
    runtime: "RUNNING", sentinel: "LIVE", provisioning: "NOT_APPLICABLE",
    lease: "NOT_READY", leaseEpoch: "NOT_APPLICABLE", leaseValidUntil: "NOT_APPLICABLE",
  });
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (command.includes(" webui renew-synthetic-lease ")) {
      await route.fulfill({
        body: JSON.stringify({
          errno: 0,
          stdout: `${status}\nconfirmation_action=renew-synthetic-lease\nconfirmation_token=${"a".repeat(32)}\nnext_nonce=${"b".repeat(32)}`,
        }),
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
      body: JSON.stringify({ errno: 0, stdout: status }),
      contentType: "application/json",
      status: 200,
    });
  });
  await installBridge(page);

  await page.goto("/");
  const candidateA = page.locator(".candidate-status-card")
    .getByRole("button", { name: "Issue / renew candidate lease" });
  await expect(candidateA).toBeEnabled();
  await candidateA.click();
  await expect(page.locator("#confirmation-dialog")).toHaveAttribute("open", "");
  await page.getByRole("button", { name: "Cancel" }).click();

  await expect
    .poll(() =>
      page.evaluate(() => {
        const active = document.activeElement;
        return active instanceof HTMLElement
          ? `${active.dataset.action ?? ""}:${active.dataset.candidateId ?? ""}`
          : "";
      }),
    )
    .toBe("renew-synthetic-lease:");
});

test("keeps two donor candidate cards responsive without local lease controls", async ({ page }) => {
  await page.route("/api/exec", async (route) => {
    const command = route.request().postData() ?? "";
    if (!command.includes(" webui status ")) {
      await route.continue();
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        errno: 0,
        stdout: `${donorCandidateStatus("candidate-a", "READY")}\n${donorCandidateStatus("candidate-b", "READY")}`,
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
  const evidence = process.env.RKA_WEBUI_EVIDENCE_DIR;
  if (evidence !== undefined) {
    await page.screenshot({ path: `${evidence}/task-26-two-candidates-1280.png`, fullPage: true });
  }

  await page.setViewportSize({ width: 768, height: 1024 });
  const tabletA = await cards.nth(0).boundingBox();
  const tabletB = await cards.nth(1).boundingBox();
  if (tabletA === null || tabletB === null) {
    throw new Error("candidate status cards have no tablet bounds");
  }
  const tabletOverlap = tabletA.x < tabletB.x + tabletB.width
    && tabletA.x + tabletA.width > tabletB.x
    && tabletA.y < tabletB.y + tabletB.height
    && tabletA.y + tabletA.height > tabletB.y;
  if (tabletOverlap) throw new Error("candidate status cards overlap at tablet width");
  expect(await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  )).toBe(false);
  if (evidence !== undefined) {
    await page.screenshot({ path: `${evidence}/task-26-two-candidates-768.png`, fullPage: true });
  }

  await page.setViewportSize({ width: 375, height: 812 });
  const narrowA = await cards.nth(0).boundingBox();
  const narrowB = await cards.nth(1).boundingBox();
  if (narrowA === null || narrowB === null || narrowA.y + narrowA.height > narrowB.y) {
    throw new Error("candidate status cards overlap at narrow width");
  }
  expect(await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth,
  )).toBe(false);
  if (evidence !== undefined) {
    await page.screenshot({ path: `${evidence}/task-26-two-candidates-375.png`, fullPage: true });
  }

  await expect(cards.getByRole("button", { name: "Issue / renew candidate lease" })).toHaveCount(0);
});
