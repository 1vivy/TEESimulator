import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const evidenceDirectory = process.argv[2];
const control = "/data/adb/modules/tricky_store/rka-control.sh";
const actions = [
  "status",
  "role-donor",
  "role-candidate",
  "pair-direct",
  "rotate-pairing",
  "start",
  "stop",
  "recover-keystore2",
  "export-audit",
  "export-evidence",
  "quarantine",
  "cleanup",
];

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
    globalThis.ksu = { exec(command, callbackName) {
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
      if (action === "renew-synthetic-lease" && parts.length === 4) {
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

function startFirefox(port) {
  const process = spawn("firefox", ["--headless", "--remote-debugging-port", String(port), "about:blank"]);
  return new Promise((resolveEndpoint, rejectEndpoint) => {
    const timeout = setTimeout(() => rejectEndpoint(new Error("Firefox BiDi endpoint timed out")), 10_000);
    process.stderr.on("data", (chunk) => {
      const match = chunk.toString().match(/ws:\/\/[^\s]+/);
      if (match === null) return;
      clearTimeout(timeout);
      resolveEndpoint({ browser: process, endpoint: `${match[0]}/session` });
    });
    process.on("error", (error) => {
      clearTimeout(timeout);
      rejectEndpoint(error);
    });
    process.on("exit", (code) => {
      if (code !== null && code !== 0) {
        clearTimeout(timeout);
        rejectEndpoint(new Error(`Firefox exited before BiDi was ready: ${code}`));
      }
    });
  });
}

function connect(endpoint) {
  return new Promise((resolveConnection, rejectConnection) => {
    const socket = new WebSocket(endpoint);
    const pending = new Map();
    let nextId = 1;
    socket.onopen = () => {
      resolveConnection({
        close: () => socket.close(),
        send(method, params = {}) {
          return new Promise((resolveCommand, rejectCommand) => {
            const id = nextId;
            nextId += 1;
            pending.set(id, { resolve: resolveCommand, reject: rejectCommand });
            socket.send(JSON.stringify({ id, method, params }));
          });
        },
      });
    };
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      const waiter = pending.get(message.id);
      if (waiter === undefined) return;
      pending.delete(message.id);
      if (message.type === "success") waiter.resolve(message.result);
      else waiter.reject(new Error(JSON.stringify(message)));
    };
    socket.onerror = () => rejectConnection(new Error("Firefox BiDi WebSocket failed"));
  });
}

async function evaluate(connection, context, expression) {
  const response = await connection.send("script.evaluate", {
    expression,
    target: { context },
    awaitPromise: true,
    resultOwnership: "none",
  });
  if (response.type !== "success") throw new Error(JSON.stringify(response));
  return response.result.value;
}

async function click(connection, context, action) {
  const source = `(async () => {
    const button = document.querySelector('button[data-action="${action}"]');
    if (button === null) throw new Error("missing fixed action");
    button.click();
    for (let index = 0; index < 8; index += 1) await Promise.resolve();
    return JSON.stringify({ disabled: button.disabled, commandState: document.querySelector("#command-state").textContent });
  })()`;
  return JSON.parse(await evaluate(connection, context, source));
}

async function screenshot(connection, context, width, height, destination) {
  await connection.send("browsingContext.setViewport", {
    context,
    viewport: { width, height },
    devicePixelRatio: 1,
  });
  const capture = await connection.send("browsingContext.captureScreenshot", {
    context,
    origin: "document",
    format: { type: "png" },
  });
  await writeFile(destination, Buffer.from(capture.data, "base64"));
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
    let escaping;
    for (const action of actions) {
      observed.push({ action, ...(await click(connection, context, action)) });
      if (action === "quarantine") {
        escaping = JSON.parse(await evaluate(connection, context, `JSON.stringify({
          hostileExecuted: globalThis.__hostileExecuted,
          hostileText: document.querySelector("#rka-status").textContent.includes("<img src=x onerror=globalThis.__hostileExecuted=true>"),
          imageChildren: document.querySelector("#rka-status img") !== null
        })`));
        if (escaping.hostileExecuted || !escaping.hostileText || escaping.imageChildren) throw new Error("hostile bridge output escaped the text-only status renderer");
        await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/browser-375.png`);
        await screenshot(connection, context, 768, 1700, `${evidenceDirectory}/browser-768.png`);
        await screenshot(connection, context, 1280, 1500, `${evidenceDirectory}/browser-1280.png`);
      }
    }
    await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/visual-375.png`);
    await screenshot(connection, context, 768, 1700, `${evidenceDirectory}/visual-768.png`);
    await screenshot(connection, context, 1280, 1500, `${evidenceDirectory}/visual-1280.png`);
    const renewalRequested = await click(connection, context, "renew-synthetic-lease");
    if (renewalRequested.commandState !== "Confirmation required") throw new Error("renewal confirmation was not requested");
    const renewalAwaiting = JSON.parse(await evaluate(connection, context, `JSON.stringify({
      open: document.querySelector("#confirmation-dialog").open,
      state: document.querySelector("#confirmation-state").textContent,
      token: document.querySelector("#confirmation-token").textContent
    })`));
    if (!renewalAwaiting.open || renewalAwaiting.state !== "Awaiting one-time token") throw new Error("renewal confirmation was not visible");
    await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/renewal-confirmation.png`);
    const renewalAccepted = JSON.parse(await evaluate(connection, context, `(async () => {
      document.querySelector("#confirmation-input").value = document.querySelector("#confirmation-token").textContent;
      document.querySelector("#confirmation-submit").click();
      for (let index = 0; index < 8; index += 1) await Promise.resolve();
      return JSON.stringify({
        state: document.querySelector("#confirmation-state").textContent,
        token: document.querySelector("#confirmation-token").textContent,
        lease: [...document.querySelectorAll("#rka-status div")].find((box) => box.querySelector("dt").textContent === "synthetic lease")?.querySelector("dd").textContent
      });
    })()`));
    if (renewalAccepted.state !== "Protected action accepted" || renewalAccepted.token !== "" || renewalAccepted.lease !== "Active") throw new Error("renewal confirmation did not settle as active");
    await screenshot(connection, context, 375, 2300, `${evidenceDirectory}/renewal-accepted.png`);
    await evaluate(connection, context, "globalThis.__bridge.failNext = true");
    const failure = await click(connection, context, "status");
    if (failure.commandState !== "Fixed control request failed") throw new Error("command failure was not visible");
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
    if (malformedState !== "WebUI bridge response was malformed") throw new Error("malformed bridge result was not visible");
    await connection.send("browsingContext.close", { context: malformed.context });
    const bridge = JSON.parse(await evaluate(connection, context, "JSON.stringify(globalThis.__bridge)"));
    const fixedCommands = actions.map((action) => `${control} webui ${action}`);
    for (const command of fixedCommands) {
      if (!bridge.log.some((entry) => entry.startsWith(command))) throw new Error(`missing clicked command: ${command}`);
    }
    if (new Set(bridge.mutationNonces).size !== bridge.mutationNonces.length) throw new Error("mutation nonce was reused");
    if (observed.some((entry) => entry.disabled)) throw new Error("button remained busy after command completion");
    if (observed.some((entry) => entry.commandState !== (entry.action === "status" ? "Status refreshed" : "Request accepted"))) throw new Error("fixed action did not render a successful completion");
    await evaluate(connection, context, "globalThis.__bridge.deferNext = true");
    const busy = await click(connection, context, "status");
    if (!busy.disabled) throw new Error("button did not render busy during a pending bridge request");
    const settled = JSON.parse(await evaluate(connection, context, `(async () => {
      globalThis.__bridge.resolveDeferred();
      for (let index = 0; index < 8; index += 1) await Promise.resolve();
      const button = document.querySelector('button[data-action="status"]');
      return JSON.stringify({ disabled: button.disabled, commandState: document.querySelector("#command-state").textContent });
    })()`));
    if (settled.disabled || settled.commandState !== "Status refreshed") throw new Error("button did not settle after the pending bridge request");
    await writeFile(`${evidenceDirectory}/browser-action-log.json`, JSON.stringify({ bridge, observed, escaping, renewalRequested, renewalAwaiting, renewalAccepted, failure, malformedState, busy, settled }, null, 2) + "\n");
  } finally {
    if (connection !== undefined && context !== undefined) {
      try { await connection.send("browsingContext.close", { context }); } catch {}
    }
    connection?.close();
    browser.kill("SIGTERM");
  }
}

await main();
