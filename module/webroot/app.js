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
    "quarantine_count",
  ]);
  const labels = Object.freeze({
    CANDIDATE: "Candidate",
    DISABLED: "Disabled",
    DIAGNOSTIC_ONLY: "Diagnostic only",
    DIRECT_NETWORK: "Direct network",
    DONOR: "Donor",
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
  let profileRole = "";
  let callbackSequence = 0;
  const bridgeCallbacks = Object.create(null);
  globalThis.__teesimulatorRkaCallbacks = bridgeCallbacks;
  const status = document.querySelector("#rka-status");
  const operation = document.querySelector("#command-state");
  const dialog = document.querySelector("#confirmation-dialog");
  const dialogState = document.querySelector("#confirmation-state");
  const token = document.querySelector("#confirmation-token");
  const input = document.querySelector("#confirmation-input");
  const submit = document.querySelector("#confirmation-submit");
  const provision = document.querySelector('button[data-action="provision-rkp"]');
  let currentRole = "";

  function parse(stdout) {
    const values = new Map();
    for (const line of String(stdout).split("\n")) {
      const index = line.indexOf("=");
      if (index > 0) values.set(line.slice(0, index), line.slice(index + 1));
    }
    return values;
  }

  function readable(value) {
    return labels[value] ?? value;
  }

  function render(values) {
    currentRole = values.get("role") ?? "";
    provision.disabled = currentRole !== "DONOR";
    status.replaceChildren();
    for (const name of displayed) {
      const box = document.createElement("div");
      const dt = document.createElement("dt");
      const dd = document.createElement("dd");
      dt.textContent = name.replaceAll("_", " ");
      dd.textContent = readable(values.get(name) ?? "UNAVAILABLE");
      if (name === "role") dd.setAttribute("aria-label", "rka-role-value");
      if (name === "direct_readiness") dd.setAttribute("aria-label", "rka-connection-value");
      box.append(dt, dd);
      status.append(box);
    }
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
      bridgeCallbacks[name] = (errno, stdout, stderr) => {
        delete bridgeCallbacks[name];
        resolve({ errno, stdout, stderr });
      };
      try {
        bridge.exec(command, `globalThis.__teesimulatorRkaCallbacks.${name}`);
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

  async function invoke(action, confirmation = "") {
    if (!Object.hasOwn(actions, action) || nonce === "") throw new Error("WebUI request was rejected");
    let commandAction = actions[action];
    if (action === "profile-validate" || action === "profile-apply") {
      if (profileRole === "") throw new Error("Select a valid profile first");
      commandAction = `${commandAction}-${profileRole.toLowerCase()}`;
    }
    const suffix = confirmation === "" ? "" : ` ${confirmation}`;
    const response = checked(await exec(`${control} webui ${commandAction} ${nonce}${suffix}`));
    if (response.errno !== 0) throw new Error("Fixed control request failed");
    const values = parse(response.stdout);
    const next = values.get("next_nonce");
    if (next !== undefined) {
      if (!/^[0-9a-f]{32}$/.test(next)) throw new Error("WebUI session rotation was invalid");
      nonce = next;
    }
    render(values);
    const requested = values.get("confirmation_token");
    if (requested !== undefined) {
      pending = action;
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
      await invoke(button.dataset.action);
    } catch (error) {
      operation.textContent = error instanceof Error ? error.message : "WebUI request failed";
    } finally {
      button.disabled = button === provision && currentRole !== "DONOR";
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
        await invoke(action, input.value);
        pending = "";
        submit.textContent = "Close";
        setConfirmationState("accepted", "Protected action accepted");
      } catch (error) {
        pending = "";
        submit.textContent = "Close";
        setConfirmationState("refused", "Protected action refused");
        operation.textContent = error instanceof Error ? error.message : "WebUI request failed";
      } finally {
        submit.disabled = false;
        input.disabled = false;
      }
    })();
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
    nonce = parse(opened.stdout).get("nonce") ?? "";
    if (opened.errno !== 0 || !/^[0-9a-f]{32}$/.test(nonce)) {
      throw new Error("WebUI session was rejected");
    }
    await invoke("status");
  })().catch((error) => {
    operation.textContent = error instanceof Error ? error.message : "WebUI unavailable";
  });
})();
