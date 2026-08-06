import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";

export function startFirefox(port) {
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

export function connect(endpoint) {
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

export async function evaluate(connection, context, expression) {
  const response = await connection.send("script.evaluate", {
    expression,
    target: { context },
    awaitPromise: true,
    resultOwnership: "none",
  });
  if (response.type !== "success") throw new Error(JSON.stringify(response));
  return response.result.value;
}

export async function click(connection, context, action, settle = true) {
  const settleSource = settle
    ? `for (let index = 0; index < 120 && button.getAttribute("aria-busy") === "true"; index += 1) {
         await new Promise((done) => requestAnimationFrame(done));
       }`
    : `for (let index = 0; index < 120 && typeof globalThis.__bridge?.resolveDeferred !== "function"; index += 1) {
         await new Promise((done) => requestAnimationFrame(done));
       }`;
  const source = `(async () => {
    const button = [...document.querySelectorAll("button[data-action]")].find(
      (candidate) => candidate.dataset.action === ${JSON.stringify(action)}
    );
    if (button === undefined) throw new Error("missing fixed action");
    button.click();
    ${settleSource}
    return JSON.stringify({
      disabled: button.disabled,
      commandState: document.querySelector("#command-state").textContent
    });
  })()`;
  return JSON.parse(await evaluate(connection, context, source));
}

export async function screenshot(connection, context, width, height, destination) {
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
  const rendered = JSON.parse(await evaluate(connection, context, `JSON.stringify({
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
    documentWidth: document.documentElement.scrollWidth,
    documentHeight: document.documentElement.scrollHeight
  })`));
  return { file: destination.split("/").at(-1), requested: { width, height }, rendered };
}
