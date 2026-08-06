import type { Page } from "@playwright/test";
import { randomUUID } from "node:crypto";

export const donorStatus = [
  "role=DONOR",
  "phone_role=PHONE_A_DONOR",
  "profile_epoch=0",
  "direct_profile=DIRECT_NETWORK",
  "direct_readiness=NOT_READY",
  "pairing=PAIRED",
  "diagnostic=DIAGNOSTIC_ONLY",
  "runtime=STOPPED",
  "sentinel=NOT_READY",
  "rkp_provisioning=PROVISIONED",
  "synthetic_lease=NOT_APPLICABLE",
  "lease_epoch=NOT_APPLICABLE",
  "lease_next=EMPTY",
  "lease_valid_until_millis=NOT_APPLICABLE",
  "quarantine_count=0",
  "network_peer_ip=100.64.0.2",
  "network_local_ip=100.64.0.1",
  "network_port=37373",
].join("\n");

export const donorCandidateStatus = (candidate: string, readiness: "NOT_READY" | "READY") =>
  [
    `candidate_begin=${candidate}`,
    `candidate_id=${candidate}`,
    "role=DONOR",
    "phone_role=PHONE_A_DONOR",
    "profile_epoch=0",
    "direct_profile=DIRECT_NETWORK",
    `direct_readiness=${readiness}`,
    "pairing=PAIRED",
    "diagnostic=DIAGNOSTIC_ONLY",
    `runtime=${readiness === "READY" ? "RUNNING" : "STOPPED"}`,
    "sentinel=LIVE",
    "rkp_provisioning=PROVISIONED",
    "synthetic_lease=NOT_APPLICABLE",
    "lease_epoch=NOT_APPLICABLE",
    "lease_next=EMPTY",
    "lease_valid_until_millis=NOT_APPLICABLE",
    "quarantine_count=0",
    "network_peer_ip=100.64.0.2",
    "network_local_ip=100.64.0.1",
    "network_port=37373",
    `candidate_end=${candidate}`,
  ].join("\n");

type SingleStatus = {
  readonly role: "LOCAL" | "DONOR" | "CANDIDATE";
  readonly phoneRole: "LOCAL_LEGACY" | "PHONE_A_DONOR" | "PHONE_B_CANDIDATE";
  readonly readiness: "NOT_READY" | "READY";
  readonly runtime: "RUNNING" | "STOPPED" | "QUARANTINED_AMBIGUOUS_MUTATION";
  readonly sentinel: "LIVE" | "NOT_READY";
  readonly provisioning: "NOT_READY" | "NOT_APPLICABLE" | "PROVISIONED";
  readonly lease: "NOT_READY" | "NOT_APPLICABLE" | "ACTIVE";
  readonly leaseEpoch: string;
  readonly leaseValidUntil: string;
  readonly quarantineCount?: number;
  readonly nextNonce?: string;
};

export const singleStatus = (status: SingleStatus): string => {
  const lines = [
    `role=${status.role}`,
    `phone_role=${status.phoneRole}`,
    "profile_epoch=0",
    `direct_profile=${status.role === "LOCAL" ? "UNAVAILABLE" : "DIRECT_NETWORK"}`,
    `direct_readiness=${status.readiness}`,
    `pairing=${status.role === "LOCAL" ? "UNPAIRED" : "PAIRED"}`,
    "diagnostic=DIAGNOSTIC_ONLY",
    `runtime=${status.runtime}`,
    `sentinel=${status.sentinel}`,
    `rkp_provisioning=${status.provisioning}`,
    `synthetic_lease=${status.lease}`,
    `lease_epoch=${status.leaseEpoch}`,
    "lease_next=EMPTY",
    `lease_valid_until_millis=${status.leaseValidUntil}`,
    `quarantine_count=${status.quarantineCount ?? 0}`,
    "network_peer_ip=100.64.0.2",
    "network_local_ip=100.64.0.1",
    "network_port=37373",
  ];
  if (status.nextNonce !== undefined) {
    lines.push(`next_nonce=${status.nextNonce}`);
  }
  return lines.join("\n");
};

export const installBridge = async (page: Page): Promise<string> => {
  const sessionId = randomUUID();
  await page.addInitScript((testSessionId) => {
    globalThis.ksu = {
      exec: async (command: string, options: string, callback: string) => {
        if (options !== "{}") {
          throw new TypeError("KernelSU options must be serialized JSON");
        }
        const response = await fetch("/api/exec", {
          body: JSON.stringify({ command, options }),
          headers: {
            "content-type": "application/json",
            "x-rka-test-session": testSessionId,
          },
          method: "POST",
        });
        const result: unknown = await response.json();
        if (
          result === null ||
          typeof result !== "object" ||
          !("errno" in result) ||
          !("stdout" in result) ||
          typeof result.stdout !== "string"
        ) {
          throw new TypeError("Mock bridge response was malformed");
        }
        const errno = result.errno;
        const stderr = "stderr" in result && typeof result.stderr === "string" ? result.stderr : "";
        if (typeof errno !== "number" && typeof errno !== "string") {
          throw new TypeError("Mock bridge errno was malformed");
        }
        const callbackName = callback.slice(callback.lastIndexOf(".") + 1);
        const receiver = globalThis.__teesimulatorRkaCallbacks[callbackName];
        if (receiver === undefined) {
          throw new TypeError("KernelSU callback was unavailable");
        }
        receiver(errno, result.stdout, stderr);
      },
    };
  }, sessionId);
  return sessionId;
};
