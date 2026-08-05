(() => {
  "use strict";

  const control = "/data/adb/modules/tricky_store/rka-control.sh";
  const actions = Object.freeze({
    status: "status",
    "role-donor": "role-donor",
    "role-candidate": "role-candidate",
    "profile-validate": "profile-validate",
    "profile-apply": "profile-apply",
    "pair-direct": "pair-direct",
    "rotate-pairing": "rotate-pairing",
    "provision-rkp": "provision-rkp",
    "renew-synthetic-lease": "renew-synthetic-lease",
    "rotate-attestation-roots": "rotate-attestation-roots",
    start: "start",
    stop: "stop",
    "recover-keystore2": "recover-keystore2",
    "recover-rkpd": "recover-rkpd",
    "export-audit": "export-audit",
    "export-evidence": "export-evidence",
    cleanup: "cleanup",
    quarantine: "quarantine",
  });
  const displayed = Object.freeze([
    "role",
    "phone_role",
    "profile_epoch",
    "direct_profile",
    "direct_readiness",
    "pairing",
    "diagnostic",
    "runtime",
    "sentinel",
    "rkp_provisioning",
    "synthetic_lease",
    "lease_epoch",
    "lease_next",
    "lease_valid_until_millis",
    "quarantine_count",
  ]);
  const labels = Object.freeze({
    CANDIDATE: "Candidate",
    ACTIVE: "Active",
    DISABLED: "Disabled",
    DIAGNOSTIC_ONLY: "Diagnostic only",
    DIRECT_NETWORK: "Direct network",
    DONOR: "Donor",
    EMPTY: "Empty",
    FAILED_CRASH_CAP: "Stopped · crash limit reached",
    INERT: "Inert",
    LIVE: "Live",
    LOCAL: "Local",
    LOCAL_LEGACY: "Local · legacy",
    NOT_READY: "Not ready",
    NOT_APPLICABLE: "Not applicable",
    PAIRED: "Paired",
    PENDING: "Pending",
    PHONE_A_DONOR: "Phone A · donor",
    PHONE_B_CANDIDATE: "Phone B · candidate",
    QUARANTINED_AMBIGUOUS_MUTATION: "Quarantined · ambiguous mutation",
    PROVISIONED: "Provisioned",
    READY: "Ready",
    RUNNING: "Running",
    STOPPED: "Stopped",
    UNAVAILABLE: "Unavailable",
    UNPAIRED: "Unpaired",
  });

  let nonce = "";
  let pending = "";
  let pendingCandidate = "";
  let focusAction = "";
  let focusCandidate = "";
  let profileRole = "";
  let callbackSequence = 0;
  const bridgeCallbacks = Object.create(null);
  globalThis.__teesimulatorRkaCallbacks = bridgeCallbacks;
  const statusList = document.querySelector("#rka-status-list");
  const operation = document.querySelector("#command-state");
  const dialog = document.querySelector("#confirmation-dialog");
  const dialogState = document.querySelector("#confirmation-state");
  const token = document.querySelector("#confirmation-token");
  const input = document.querySelector("#confirmation-input");
  const submit = document.querySelector("#confirmation-submit");
  const provision = document.querySelector('button[data-action="provision-rkp"]');
  const candidateLeaseAction = document.querySelector("#candidate-lease-action");
  const candidateStates = new Map();
  let currentRole = "";

  function parse(stdout) {
    const values = new Map();
    const candidates = [];
    let candidate = null;
    for (const line of String(stdout).split("\n")) {
      const index = line.indexOf("=");
      if (index <= 0) continue;
      const name = line.slice(0, index);
      const value = line.slice(index + 1);
      if (name === "candidate_begin") {
        if (candidate !== null) throw new Error("Candidate status blocks overlapped");
        candidate = new Map([[name, value]]);
      } else if (name === "candidate_end") {
        if (
          candidate === null ||
          candidate.get("candidate_begin") !== value ||
          candidate.get("candidate_id") !== value
        ) {
          throw new Error("Candidate status block was invalid");
        }
        candidates.push(candidate);
        candidate = null;
      } else {
        (candidate ?? values).set(name, value);
      }
    }
    if (candidate !== null) throw new Error("Candidate status block was incomplete");
    if (candidates.length === 0 && displayed.some((name) => values.has(name))) {
      candidates.push(values);
    }
    return { values, candidates };
  }

  function readable(value) {
    if (/^STAGED_[0-9]+$/.test(value)) return `Staged · epoch ${value.slice(7)}`;
    return labels[value] ?? value;
  }

  function readableStatus(name, value) {
    if (name !== "lease_valid_until_millis" || !/^[0-9]{1,16}$/.test(value)) {
      return readable(value);
    }
    const millis = Number(value);
    const date = new Date(millis);
    return Number.isSafeInteger(millis) && !Number.isNaN(date.valueOf())
      ? date.toLocaleString()
      : "Unavailable";
  }

  function updateRoleControls() {
    provision.disabled = currentRole !== "DONOR";
    for (const renew of statusList.querySelectorAll('button[data-action="renew-synthetic-lease"]')) {
      const candidate = candidateStates.get(renew.dataset.candidateId ?? "");
      renew.disabled = !(
        candidate?.get("role") === "CANDIDATE" &&
        candidate.get("direct_readiness") === "READY" &&
        (candidate.get("synthetic_lease") === "NOT_READY" ||
          candidate.get("synthetic_lease") === "ACTIVE") &&
        candidate.get("lease_next") === "EMPTY"
      );
    }
  }

  function render(candidates) {
    currentRole = candidates[0]?.get("role") ?? "";
    candidateStates.clear();
    statusList.replaceChildren();
    for (const [candidateIndex, values] of candidates.entries()) {
      const candidateId = values.get("candidate_id") ?? "";
      const candidateKey = candidateId === "" ? `legacy-${candidateIndex}` : candidateId;
      const headingId = `candidate-status-heading-${candidateIndex}`;
      candidateStates.set(candidateId, values);
      const card = document.createElement("section");
      card.className = "candidate-status-card";
      card.dataset.candidateId = candidateId;
      card.setAttribute("aria-labelledby", headingId);
      const heading = document.createElement("div");
      heading.className = "candidate-card-heading";
      const label = document.createElement("p");
      label.className = "eyebrow";
      label.textContent = candidateId === "" ? "Local status" : "Paired candidate";
      const title = document.createElement("h3");
      title.id = headingId;
      title.textContent = candidateId === "" ? "Current device" : candidateId;
      heading.append(label, title);
      const status = document.createElement("dl");
      status.className = "status-grid";
      status.setAttribute("aria-live", "polite");
      for (const name of displayed) {
        const box = document.createElement("div");
        const dt = document.createElement("dt");
        const dd = document.createElement("dd");
        dt.textContent = name.replaceAll("_", " ");
        dd.textContent = readableStatus(name, values.get(name) ?? "UNAVAILABLE");
        if (name === "role") {
          dd.setAttribute(
            "aria-label",
            candidateId === "" ? "rka-role-value" : `rka-role-value-${candidateKey}`,
          );
        }
        if (name === "direct_readiness") {
          dd.setAttribute(
            "aria-label",
            candidateId === "" ? "rka-connection-value" : `rka-connection-value-${candidateKey}`,
          );
        }
        box.append(dt, dd);
        status.append(box);
      }
      const renew = candidateLeaseAction.content.firstElementChild?.cloneNode(true);
      if (!(renew instanceof HTMLButtonElement)) throw new Error("Candidate lease action was unavailable");
      if (candidateId !== "") renew.dataset.candidateId = candidateId;
      renew.addEventListener("click", () => {
        void handle(renew);
      });
      card.append(heading, status, renew);
      statusList.append(card);
    }
    updateRoleControls();
  }

  function setConfirmationState(state, message) {
    dialog.dataset.state = state;
    dialogState.textContent = message;
  }

  function exec(command) {
    const bridge = globalThis.ksu;
    if (!bridge || typeof bridge.exec !== "function") {
      return Promise.reject(new Error("KernelSU WebUI bridge unavailable"));
    }
    return new Promise((resolve, reject) => {
      callbackSequence += 1;
      const name = `request${callbackSequence}`;
      let settled = false;
      const settle = (value) => {
        if (settled) return;
        settled = true;
        delete bridgeCallbacks[name];
        resolve(value);
      };
      bridgeCallbacks[name] = (errno, stdout, stderr) => {
        settle({ errno, stdout, stderr });
      };
      try {
        const returned = bridge.exec(command, `globalThis.__teesimulatorRkaCallbacks.${name}`);
        if (returned && typeof returned.then === "function") {
          returned.then(settle, reject);
        }
      } catch (error) {
        delete bridgeCallbacks[name];
        reject(error);
      }
    });
  }

  function checked(value) {
    const errno =
      typeof value?.errno === "string" && /^(?:0|[1-9][0-9]{0,2})$/.test(value.errno)
        ? Number(value.errno)
        : value?.errno;
    if (
      value === null ||
      typeof value !== "object" ||
      !Number.isSafeInteger(errno) ||
      errno < 0 ||
      errno > 255 ||
      typeof value.stdout !== "string"
    ) {
      throw new Error("WebUI bridge response was malformed");
    }
    return { errno, stdout: value.stdout, stderr: value.stderr };
  }

  async function invoke(action, confirmation = "", candidate = "") {
    if (!Object.hasOwn(actions, action) || nonce === "") throw new Error("WebUI request was rejected");
    if (candidate !== "" && !/^[A-Za-z0-9._:-]+$/.test(candidate)) {
      throw new Error("Candidate selector was invalid");
    }
    let commandAction = actions[action];
    if (action === "profile-validate" || action === "profile-apply") {
      if (profileRole === "") throw new Error("Select a valid profile first");
      commandAction = `${commandAction}-${profileRole.toLowerCase()}`;
    }
    const suffix = confirmation === "" ? "" : ` ${confirmation}`;
    const candidateSuffix = candidate === "" ? "" : ` --candidate ${candidate}`;
    const response = checked(
      await exec(`${control} webui ${commandAction} ${nonce}${suffix}${candidateSuffix}`),
    );
    if (response.errno !== 0) throw new Error("Fixed control request failed");
    const parsed = parse(response.stdout);
    const values = parsed.values;
    const next = values.get("next_nonce");
    if (next !== undefined) {
      if (!/^[0-9a-f]{32}$/.test(next)) throw new Error("WebUI session rotation was invalid");
      nonce = next;
    }
    render(parsed.candidates);
    const requested = values.get("confirmation_token");
    if (requested !== undefined) {
      pending = action;
      pendingCandidate = candidate;
      focusAction = action;
      focusCandidate = candidate;
      token.textContent = requested;
      input.value = "";
      submit.textContent = "Confirm action";
      submit.disabled = false;
      setConfirmationState("awaiting-token", "Awaiting one-time token");
      dialog.showModal();
      input.focus();
      operation.textContent = "Confirmation required";
      return;
    }
    operation.textContent = action === "status" ? "Status refreshed" : "Request accepted";
  }

  async function handle(button) {
    button.disabled = true;
    try {
      await invoke(button.dataset.action, "", button.dataset.candidateId ?? "");
    } catch (error) {
      operation.textContent = error instanceof Error ? error.message : "WebUI request failed";
    } finally {
      button.disabled = false;
      updateRoleControls();
    }
  }

  submit.addEventListener("click", () => {
    void (async () => {
      if (dialog.dataset.state === "accepted" || dialog.dataset.state === "refused") {
        dialog.close();
        return;
      }
      if (pending === "" || input.value !== token.textContent) {
        setConfirmationState("mismatch", "Token mismatch · request not sent");
        operation.textContent = "Confirmation token did not match";
        return;
      }
      const action = pending;
      submit.disabled = true;
      input.disabled = true;
      setConfirmationState("busy", "Applying protected action");
      try {
        await invoke(action, input.value, pendingCandidate);
        pending = "";
        pendingCandidate = "";
        token.textContent = "";
        input.value = "";
        submit.textContent = "Close";
        setConfirmationState("accepted", "Protected action accepted");
      } catch (error) {
        pending = "";
        pendingCandidate = "";
        token.textContent = "";
        input.value = "";
        submit.textContent = "Close";
        setConfirmationState("refused", "Protected action refused");
        operation.textContent = error instanceof Error ? error.message : "WebUI request failed";
      } finally {
        submit.disabled = false;
        input.disabled = false;
      }
    })();
  });

  // Re-rendering candidate cards detaches the triggering control, so the dialog's native
  // return-focus has nothing to restore; re-resolve the equivalent live control instead.
  dialog.addEventListener("close", () => {
    if (focusAction === "") return;
    const restored = Array.from(document.querySelectorAll("button[data-action]")).find(
      (control) =>
        control.dataset.action === focusAction &&
        (control.dataset.candidateId ?? "") === focusCandidate,
    );
    focusAction = "";
    focusCandidate = "";
    if (restored instanceof HTMLButtonElement) restored.focus();
  });

  for (const button of document.querySelectorAll("button[data-action]")) {
    button.addEventListener("click", () => {
      void handle(button);
    });
  }

  document.querySelector("#profile-file").addEventListener("change", (event) => {
    void (async () => {
      const file = event.target.files?.[0];
      if (file === undefined) {
        profileRole = "";
        return;
      }
      try {
        const value = JSON.parse(await file.text());
        const valid =
          value !== null &&
          typeof value === "object" &&
          value.version === 1 &&
          (value.role === "DONOR" || value.role === "CANDIDATE") &&
          Number.isSafeInteger(value.profile_epoch) &&
          value.profile_epoch >= 0 &&
          value.transport === "DIRECT_NETWORK" &&
          Object.keys(value).length === 4;
        if (!valid) throw new Error("invalid");
        profileRole = value.role;
        operation.textContent = "Profile loaded, not applied";
      } catch {
        profileRole = "";
        operation.textContent = "Profile file was invalid";
      }
    })();
  });

  void (async () => {
    const opened = checked(await exec(`${control} webui-open`));
    nonce = parse(opened.stdout).values.get("nonce") ?? "";
    if (opened.errno !== 0 || !/^[0-9a-f]{32}$/.test(nonce)) {
      throw new Error("WebUI session was rejected");
    }
    await invoke("status");
  })().catch((error) => {
    operation.textContent = error instanceof Error ? error.message : "WebUI unavailable";
  });
})();
