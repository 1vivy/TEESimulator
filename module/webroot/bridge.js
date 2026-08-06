(function (global) {
  "use strict";

  var sequence = 0;
  var callbacks = Object.create(null);
  global.__teesimulatorRkaCallbacks = callbacks;

  function BridgeTimeoutError(message) {
    this.name = "BridgeTimeoutError";
    this.message = message;
    if (Error.captureStackTrace) Error.captureStackTrace(this, BridgeTimeoutError);
  }
  BridgeTimeoutError.prototype = Object.create(Error.prototype);
  BridgeTimeoutError.prototype.constructor = BridgeTimeoutError;

  function execute(command, timeoutMillis) {
    var bridge = global.ksu;
    if (!bridge || typeof bridge.exec !== "function") {
      return Promise.reject(new Error("KernelSU WebUI bridge unavailable"));
    }
    var timeout = typeof timeoutMillis === "number" ? timeoutMillis : 30000;
    return new Promise(function (resolve, reject) {
      sequence += 1;
      var name = "request" + sequence;
      var settled = false;
      var timer = global.setTimeout(function () {
        finishReject(new BridgeTimeoutError("The device did not report an outcome. Reopen this page before another action."));
      }, timeout);

      function cleanup() {
        global.clearTimeout(timer);
        delete callbacks[name];
      }

      function finishResolve(errno, stdout, stderr) {
        if (settled) return;
        settled = true;
        cleanup();
        resolve({ errno: errno, stdout: stdout, stderr: stderr });
      }

      function finishReject(error) {
        if (settled) return;
        settled = true;
        cleanup();
        reject(error instanceof Error ? error : new Error("KernelSU bridge failed"));
      }

      callbacks[name] = finishResolve;
      try {
        var returned = bridge.exec(command, JSON.stringify({}), "globalThis.__teesimulatorRkaCallbacks." + name);
        if (returned && typeof returned.then === "function") returned.then(function () {}, finishReject);
      } catch (error) {
        finishReject(error);
      }
    });
  }

  function callbackCount() {
    return Object.keys(callbacks).length;
  }

  global.RkaBridge = Object.freeze({
    BridgeTimeoutError: BridgeTimeoutError,
    callbackCount: callbackCount,
    execute: execute
  });
})(globalThis);
