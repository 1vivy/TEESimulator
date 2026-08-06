import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { click, connect, evaluate, screenshot, startFirefox } from "./webui_browser_support.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const evidenceDirectory = process.argv[2];
const control = "/data/adb/modules/tricky_store/rka-control.sh";
const actions = [
  "status",
  "role-donor",
  "provision-rkp",
  "role-candidate",
  "pair-direct",
  "rotate-pairing",
  "start",
  "stop",
  "rotate-attestation-roots",
  "recover-keystore2",
  "recover-rkpd",
  "export-audit",
  "export-evidence",
  "quarantine",
  "cleanup",
];
const protectedActions = new Set([
  "provision-rkp",
  "rotate-attestation-roots",
  "recover-keystore2",
  "recover-rkpd",
  "cleanup",
]);

if (evidenceDirectory === undefined) throw new Error("missing evidence directory");

function status(role = "DONOR", hostile = false) {
  return [
    `role=${hostile ? "<img src=x onerror=globalThis.__hostileExecuted=true>" : role}`,
    `phone_role=${role === "CANDIDATE" ? "PHONE_B_CANDIDATE" : "PHONE_A_DONOR"}`,
    "profile_epoch=0",
    "direct_profile=DIRECT_NETWORK",
    "direct_readiness=READY",
    "pairing=PAIRED",
    "diagnostic=DIAGNOSTIC_ONLY",
    "runtime=RUNNING",
    "sentinel=LIVE",
    `rkp_provisioning=${role === "DONOR" ? "PROVISIONED" : "NOT_APPLICABLE"}`,
    `synthetic_lease=${role === "CANDIDATE" ? "ACTIVE" : "NOT_APPLICABLE"}`,
    `lease_epoch=${role === "CANDIDATE" ? "0" : "NOT_APPLICABLE"}`,
    "lease_next=EMPTY",
    `lease_valid_until_millis=${role === "CANDIDATE" ? "1800000000000" : "NOT_APPLICABLE"}`,
    "quarantine_count=0",
  ].join("\n") + "\n";
}

function bridgePreload() {
  return `() => {
    let nonce = "1".padStart(32, "0");
    let counter = 1;
    let role = "DONOR";
    let protectedAction = "";
    const confirmationToken = "0123456789abcdef0123456789abcdef";
    const control = ${JSON.stringify(control)};
    const status = (hostile = false) => [
      "role=" + (hostile ? "<img src=x onerror=globalThis.__hostileExecuted=true>" : role),
      "phone_role=" + (role === "CANDIDATE" ? "PHONE_B_CANDIDATE" : "PHONE_A_DONOR"),
      "profile_epoch=0",
      "direct_profile=DIRECT_NETWORK",
      "direct_readiness=READY",
      "pairing=PAIRED",
      "diagnostic=DIAGNOSTIC_ONLY",
      "runtime=RUNNING",
      "sentinel=LIVE",
      "rkp_provisioning=" + (role === "DONOR" ? "PROVISIONED" : "NOT_APPLICABLE"),
      "synthetic_lease=" + (role === "CANDIDATE" ? "ACTIVE" : "NOT_APPLICABLE"),
      "lease_epoch=" + (role === "CANDIDATE" ? "0" : "NOT_APPLICABLE"),
      "lease_next=EMPTY",
      "lease_valid_until_millis=" + (role === "CANDIDATE" ? "1800000000000" : "NOT_APPLICABLE"),
      "quarantine_count=0",
      ""
    ].join("\\n");
    globalThis.__hostileExecuted = false;
    globalThis.__bridge = { log: [], failNext: false, deferNext: false, resolveDeferred: null, mutationNonces: [] };
    globalThis.confirm = () => true;
    function callback(name, errno, stdout, stderr = "") {
      const match = /^globalThis\\.__teesimulatorRkaCallbacks\\.(request[1-9][0-9]*)$/.exec(name);
      if (match === null) throw new Error("unsafe callback expression");
      queueMicrotask(() => globalThis.__teesimulatorRkaCallbacks[match[1]](String(errno), stdout, stderr));
    }
    globalThis.ksu = { exec(command, options, callbackName) {
      if (typeof options !== "string" || typeof callbackName !== "string") throw new Error("invalid KernelSU bridge call");
      globalThis.__bridge.log.push(command);
      if (location.hash === "#malformed") {
        callback(callbackName, "invalid", status());
        return;
      }
      if (globalThis.__bridge.deferNext) {
        globalThis.__bridge.deferNext = false;
        globalThis.__bridge.resolveDeferred = () => callback(callbackName, 0, status());
        return;
      }
      if (globalThis.__bridge.failNext) {
        globalThis.__bridge.failNext = false;
        callback(callbackName, 1, "");
        return;
      }
      if (command === control + " webui-open") {
        callback(callbackName, 0, "nonce=" + nonce + "\\n");
        return;
      }
      const parts = command.split(" ");
      if ((parts.length !== 4 && parts.length !== 5) || parts[0] !== control || parts[1] !== "webui" || !/^[a-z0-9-]+$/.test(parts[2]) || !/^[0-9a-f]{32}$/.test(parts[3])) {
        callback(callbackName, 1, "");
        return;
      }
      const action = parts[2];
      const supplied = parts[3];
      if (action === "status" || action === "quarantine") {
        callback(callbackName, supplied === nonce ? 0 : 1, supplied === nonce ? status(action === "quarantine") : "");
        return;
      }
      if (supplied !== nonce) {
        callback(callbackName, 1, "");
        return;
      }
      globalThis.__bridge.mutationNonces.push(supplied);
       if (${JSON.stringify([...protectedActions, "renew-synthetic-lease"])}.includes(action) && parts.length === 4) {
        protectedAction = action;
        counter += 1;
        nonce = counter.toString(16).padStart(32, "0");
        callback(callbackName, 0, "confirmation_action=" + action + "\\nconfirmation_token=" + confirmationToken + "\\n" + status() + "next_nonce=" + nonce + "\\n");
        return;
      }
      if (parts.length === 5) {
        if (action !== protectedAction || parts[4] !== confirmationToken) {
          callback(callbackName, 1, "");
          return;
        }
        protectedAction = "";
      }
      if (action === "role-candidate") role = "CANDIDATE";
      if (action === "role-donor") role = "DONOR";
      counter += 1;
      nonce = counter.toString(16).padStart(32, "0");
      callback(callbackName, 0, status() + "next_nonce=" + nonce + "\\n");
    }};
  }`;
}

async function main() {
  await mkdir(evidenceDirectory, { recursive: true, mode: 0o700 });
  const port = 9400 + (process.pid % 200);
  const { browser, endpoint } = await startFirefox(port);
  let connection;
  let context;
  try {
    connection = await connect(endpoint);
    await connection.send("session.new", { capabilities: { alwaysMatch: {} } });
    await connection.send("script.addPreloadScript", { functionDeclaration: bridgePreload() });
    const created = await connection.send("browsingContext.create", { type: "tab" });
    context = created.context;
    const url = `file://${repositoryRoot}/module/webroot/index.html`;
    await connection.send("browsingContext.navigate", { context, url, wait: "complete" });
    const readyState = await evaluate(connection, context, `(async () => {
      for (let index = 0; index < 16; index += 1) {
        await Promise.resolve();
        const value = document.querySelector("#command-state").textContent;
        if (value !== "Connecting") return value;
      }
      return "Connecting";
    })()`);
    if (readyState !== "Status refreshed") throw new Error(`WebUI initial state: ${readyState}`);
    const observed = [];
    const viewportEvidence = [];
    let escaping;
    for (const action of actions) {
      const clicked = await click(connection, context, action);
      if (protectedActions.has(action)) {
        if (clicked.commandState !== "Confirmation required") throw new Error(`${action} confirmation was not requested`);
        const settled = JSON.parse(await evaluate(connection, context, `(async () => {
          const token = document.querySelector("#confirmation-token").textContent;
          document.querySelector("#confirmation-input").value = token;
          document.querySelector("#confirmation-submit").click();
          for (let index = 0; index < 120 && document.querySelector("#confirmation-state").textContent !== "Protected action accepted"; index += 1) {
            await new Promise((resolveFrame) => requestAnimationFrame(resolveFrame));
          }
          const result = {
            state: document.querySelector("#confirmation-state").textContent,
            fieldHidden: document.querySelector("#confirmation-field").hidden,
            cancelHidden: document.querySelector("#confirmation-cancel").hidden,
            submitText: document.querySelector("#confirmation-submit").textContent,
            commandState: document.querySelector("#command-state").textContent
          };
          document.querySelector("#confirmation-submit").click();
          return JSON.stringify(result);
        })()`));
        if (settled.state !== "Protected action accepted" || !settled.fieldHidden || !settled.cancelHidden || settled.submitText !== "Close") {
          throw new Error(`${action} confirmation did not reach an honest terminal state`);
        }
        observed.push({ action, disabled: false, commandState: settled.commandState });
      } else {
        observed.push({ action, ...clicked });
      }
      if (action === "quarantine") {
        escaping = JSON.parse(await evaluate(connection, context, `JSON.stringify({
          hostileExecuted: globalThis.__hostileExecuted,
          hostileText: document.querySelector("#rka-status-list").textContent.includes("<img src=x onerror=globalThis.__hostileExecuted=true>"),
          imageChildren: document.querySelector("#rka-status-list img") !== null
        })`));
        if (escaping.hostileExecuted || escaping.hostileText || escaping.imageChildren) throw new Error("hostile bridge output reached the status renderer");
        await evaluate(connection, context, `(async () => {
          await Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined)));
          return getComputedStyle(document.querySelector(".toast")).opacity;
        })()`);
        await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/browser-375.png`);
        await screenshot(connection, context, 768, 1700, `${evidenceDirectory}/browser-768.png`);
        await screenshot(connection, context, 1280, 1500, `${evidenceDirectory}/browser-1280.png`);
      }
    }
    viewportEvidence.push(await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/visual-375.png`));
    viewportEvidence.push(await screenshot(connection, context, 768, 1700, `${evidenceDirectory}/visual-768.png`));
    viewportEvidence.push(await screenshot(connection, context, 1280, 1500, `${evidenceDirectory}/visual-1280.png`));
    const renewalRequested = await click(connection, context, "renew-synthetic-lease");
    if (renewalRequested.commandState !== "Confirmation required") throw new Error("renewal confirmation was not requested");
    const renewalAwaiting = JSON.parse(await evaluate(connection, context, `JSON.stringify({
      open: document.querySelector("#confirmation-dialog").open,
      state: document.querySelector("#confirmation-state").textContent,
      token: document.querySelector("#confirmation-token").textContent
    })`));
    if (!renewalAwaiting.open || renewalAwaiting.state !== "Awaiting one-time token") throw new Error("renewal confirmation was not visible");
    viewportEvidence.push(await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/renewal-confirmation.png`));
    const renewalAccepted = JSON.parse(await evaluate(connection, context, `(async () => {
      document.querySelector("#confirmation-input").value = document.querySelector("#confirmation-token").textContent;
      document.querySelector("#confirmation-submit").click();
       for (let index = 0; index < 120 && document.querySelector("#confirmation-state").textContent !== "Protected action accepted"; index += 1) {
         await new Promise((resolveFrame) => requestAnimationFrame(resolveFrame));
       }
       return JSON.stringify({
         state: document.querySelector("#confirmation-state").textContent,
         token: document.querySelector("#confirmation-token").textContent,
         input: document.querySelector("#confirmation-input").value,
         fieldHidden: document.querySelector("#confirmation-field").hidden,
         cancelHidden: document.querySelector("#confirmation-cancel").hidden,
         lease: document.querySelector('[data-status-field="synthetic_lease"]')?.textContent
       });
     })()`));
    if (renewalAccepted.state !== "Protected action accepted" || renewalAccepted.token !== "" || renewalAccepted.input !== "" || !renewalAccepted.fieldHidden || !renewalAccepted.cancelHidden || renewalAccepted.lease !== "Active") throw new Error("renewal confirmation did not settle as active");
    await evaluate(connection, context, "new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)))");
    viewportEvidence.push(await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/renewal-accepted.png`));
    await evaluate(connection, context, "globalThis.__bridge.failNext = true");
    const failure = await click(connection, context, "status");
    if (failure.commandState !== "Request failed · session restored") throw new Error("command failure was not visible");
    const malformed = await connection.send("browsingContext.create", { type: "tab" });
    await connection.send("browsingContext.navigate", { context: malformed.context, url: `${url}#malformed`, wait: "complete" });
    const malformedState = await evaluate(connection, malformed.context, `(async () => {
      for (let index = 0; index < 16; index += 1) {
        await Promise.resolve();
        const value = document.querySelector("#command-state").textContent;
        if (value !== "Connecting") return value;
      }
      return "Connecting";
    })()`);
    if (malformedState !== "WebUI unavailable") throw new Error("malformed bridge result was not visible");
    await connection.send("browsingContext.close", { context: malformed.context });
    const bridge = JSON.parse(await evaluate(connection, context, "JSON.stringify(globalThis.__bridge)"));
    const fixedCommands = actions.map((action) => `${control} webui ${action}`);
    for (const command of fixedCommands) {
      if (!bridge.log.some((entry) => entry.startsWith(command))) throw new Error(`missing clicked command: ${command}`);
    }
    if (new Set(bridge.mutationNonces).size !== bridge.mutationNonces.length) throw new Error("mutation nonce was reused");
    if (observed.some((entry) => entry.disabled)) throw new Error("button remained busy after command completion");
    if (observed.some((entry) => entry.commandState !== (entry.action === "status" ? "Status refreshed" : entry.action === "quarantine" ? "Request failed · session restored" : "Request accepted"))) throw new Error("fixed action did not render its expected completion");
    await evaluate(connection, context, "globalThis.__bridge.deferNext = true");
    const busy = await click(connection, context, "status", false);
    if (!busy.disabled) throw new Error("button did not render busy during a pending bridge request");
    const settled = JSON.parse(await evaluate(connection, context, `(async () => {
      globalThis.__bridge.resolveDeferred();
      const button = document.querySelector('button[data-action="status"]');
      for (let index = 0; index < 120 && button.getAttribute("aria-busy") === "true"; index += 1) {
        await new Promise((resolveFrame) => requestAnimationFrame(resolveFrame));
      }
      return JSON.stringify({ disabled: button.disabled, commandState: document.querySelector("#command-state").textContent });
    })()`));
    if (settled.disabled || settled.commandState !== "Status refreshed") throw new Error("button did not settle after the pending bridge request");
    await writeFile(`${evidenceDirectory}/browser-action-log.json`, JSON.stringify({
      outcome: { browser: "firefox", status: "passed" },
      bridge,
      observed,
      escaping,
      viewportEvidence,
      renewalRequested,
      renewalAwaiting,
      renewalAccepted,
      failure,
      malformedState,
      busy,
      settled,
    }, null, 2) + "\n");
  } finally {
    if (connection !== undefined && context !== undefined) {
      try { await connection.send("browsingContext.close", { context }); } catch {}
    }
    connection?.close();
    browser.kill("SIGTERM");
  }
}

await main();
