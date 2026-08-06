(function (global) {
  "use strict";

  var nonce = "";
  var profileRole = "";
  var profileRevision = 0;
  var validatedProfileRevision = -1;
  var locked = false;
  var dialogBusy = false;
  var confirmation = null;
  var focusAction = "";
  var focusCandidate = "";
  var dialog = document.querySelector("#confirmation-dialog");
  var confirmationSubmit = document.querySelector("#confirmation-submit");
  var confirmationCancel = document.querySelector("#confirmation-cancel");
  var networkForm = document.querySelector("#network-form");
  var profileFile = document.querySelector("#profile-file");

  if (!(dialog instanceof HTMLDialogElement) ||
      !(confirmationSubmit instanceof HTMLButtonElement) ||
      !(confirmationCancel instanceof HTMLButtonElement) ||
      !(networkForm instanceof HTMLFormElement) ||
      !(profileFile instanceof HTMLInputElement)) {
    throw new Error("WebUI markup was incomplete");
  }

  global.RkaFeedback.initialize(
    document.querySelector("#toast-stack"),
    document.querySelector("#session-activity")
  );

  function message(error) {
    return error instanceof Error ? error.message : "WebUI request failed";
  }

  function afterPaint() {
    return new Promise(function (resolve) {
      global.requestAnimationFrame(function () {
        global.requestAnimationFrame(resolve);
      });
    });
  }

  function controlError(response) {
    var error = new Error(global.RkaModel.sanitizeDetail(response.stderr, response.errno));
    error.name = "ControlRequestError";
    return error;
  }

  async function raw(command, timeoutMillis) {
    var value = await global.RkaBridge.execute(command, timeoutMillis);
    return global.RkaModel.checkedResponse(value);
  }

  async function openSession() {
    var response = await raw(global.RkaModel.CONTROL + " webui-open");
    if (response.errno !== 0) throw controlError(response);
    var parsed = global.RkaModel.parseOutput(response.stdout);
    var opened = parsed.values.get("nonce");
    if (typeof opened !== "string") throw new Error("WebUI session was rejected");
    nonce = opened;
  }

  async function requestAction(request) {
    var built = global.RkaModel.buildCommand({
      action: request.action,
      candidate: request.candidate,
      confirmation: request.confirmation,
      network: request.network,
      nonce: nonce,
      profileRole: profileRole
    });
    var response = await raw(built.command);
    if (response.errno !== 0) throw controlError(response);
    var parsed = global.RkaModel.parseOutput(response.stdout);
    var nextNonce = parsed.values.get("next_nonce");
    if (built.metadata.mutation && typeof nextNonce !== "string") {
      throw new Error("WebUI session rotation was missing");
    }
    if (typeof nextNonce === "string") nonce = nextNonce;
    if (parsed.candidates.length > 0) global.RkaViews.renderStatus(parsed.candidates);
    var token = parsed.values.get("confirmation_token");
    var action = parsed.values.get("confirmation_action");
    if (typeof token === "string") {
      if (action !== built.metadata.shell || request.confirmation !== "") {
        throw new Error("Protected action response was invalid");
      }
      return { confirmation: token, metadata: built.metadata };
    }
    return { confirmation: "", metadata: built.metadata };
  }

  async function resyncSession() {
    await openSession();
    await requestAction({
      action: "status", candidate: "", confirmation: "", network: null
    });
  }

  async function runAction(request) {
    var metadata;
    var requestedProfileRevision = profileRevision;
    try {
      metadata = global.RkaModel.getAction(request.action, profileRole);
    } catch (error) {
      global.RkaFeedback.notice("Request not sent", message(error), "error");
      return "not-sent";
    }
    var toast = global.RkaFeedback.begin(request.button, metadata);
    global.RkaViews.setBusy(true);
    await afterPaint();
    try {
      var result = await requestAction(request);
      if (result.confirmation !== "") {
        confirmation = {
          action: request.action,
          candidate: request.candidate,
          token: result.confirmation
        };
        focusAction = request.action;
        focusCandidate = request.candidate;
        global.RkaViews.openConfirmation(result.confirmation);
        global.RkaViews.setCommandState("Confirmation required");
        global.RkaFeedback.updateToast(
          toast, "Confirmation required", "Review the one-time token in the dialog", "success"
        );
      } else {
        global.RkaViews.setCommandState(request.action === "status" ? "Status refreshed" : "Request accepted");
        global.RkaFeedback.updateToast(toast, metadata.success, "Device status refreshed", "success");
        if (metadata.activity) global.RkaFeedback.addActivity(metadata.success, "Completed");
        if (request.action === "network-save") global.RkaViews.clearNetworkDirty();
        if (request.action === "profile-validate") {
          if (requestedProfileRevision === profileRevision) {
            validatedProfileRevision = profileRevision;
            global.RkaViews.setProfileAvailability(true, true);
          } else {
            global.RkaViews.setProfileAvailability(profileRole !== "", false);
          }
        } else if (request.action === "profile-apply") {
          validatedProfileRevision = -1;
          global.RkaViews.setProfileAvailability(true, false);
        }
      }
      return "accepted";
    } catch (error) {
      var detail = message(error);
      var outcomeUnknown = request.confirmation !== "" ||
        error instanceof global.RkaBridge.BridgeTimeoutError;
      if (outcomeUnknown) {
        locked = true;
        global.RkaFeedback.updateToast(toast, "Outcome unknown", detail, "unknown");
        if (metadata.activity) global.RkaFeedback.addActivity(metadata.pending, "Unknown");
        global.RkaViews.setCommandState("Outcome unknown · reopen this page");
      } else {
        global.RkaFeedback.updateToast(toast, "Request failed", detail, "error");
        if (metadata.activity) global.RkaFeedback.addActivity(metadata.pending, "Failed");
        try {
          await resyncSession();
          global.RkaViews.setCommandState("Request failed · session restored");
        } catch (recoveryError) {
          locked = true;
          global.RkaViews.setCommandState("WebUI session unavailable");
          global.RkaFeedback.notice("Session unavailable", message(recoveryError), "error");
        }
      }
      return outcomeUnknown ? "unknown" : "not-sent";
    } finally {
      global.RkaFeedback.settleButton(request.button);
      if (!locked) global.RkaViews.setBusy(false);
    }
  }

  async function handleNetworkSubmit() {
    var values = global.RkaViews.networkValues();
    var peerMessage = "";
    var localMessage = "";
    try { values.peer = global.RkaModel.parseIpv4(values.peer); }
    catch (error) { peerMessage = message(error); }
    try { values.local = global.RkaModel.parseIpv4(values.local); }
    catch (error) { localMessage = message(error); }
    global.RkaViews.showNetworkErrors(peerMessage, localMessage);
    if (peerMessage !== "" || localMessage !== "") {
      global.RkaFeedback.notice("Check network settings", "Enter valid peer and local IPv4 addresses", "error");
      return;
    }
    var button = document.querySelector("#network-submit");
    await runAction({
      action: "network-save", button: button, candidate: "",
      confirmation: "", network: values
    });
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    var button = target instanceof Element ? target.closest("button[data-action]") : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled || locked) return;
    var action = button.dataset.action || "";
    var candidate = button.dataset.candidateId || "";
    if (action === "profile-apply" && validatedProfileRevision !== profileRevision) return;
    void runAction({
      action: action, button: button, candidate: candidate,
      confirmation: "", network: null
    });
  });

  networkForm.addEventListener("submit", function (event) {
    event.preventDefault();
    if (!locked) void handleNetworkSubmit();
  });
  networkForm.addEventListener("input", function (event) {
    if (event.target instanceof HTMLInputElement) global.RkaViews.markNetworkDirty(event.target);
  });

  global.RkaProfile.observe(profileFile, function (result) {
    profileRevision += 1;
    validatedProfileRevision = -1;
    profileRole = result.role;
    global.RkaViews.setProfileAvailability(result.ready, false);
    if (result.message !== "") global.RkaViews.setCommandState(result.message);
  });

  confirmationSubmit.addEventListener("click", function () {
    if (global.RkaViews.currentConfirmationState() === "accepted" ||
        global.RkaViews.currentConfirmationState() === "not-sent" ||
        global.RkaViews.currentConfirmationState() === "unknown") {
      global.RkaViews.closeConfirmation();
      return;
    }
    if (confirmation === null || global.RkaViews.confirmationInput() !== confirmation.token) {
      global.RkaViews.setConfirmationState("mismatch", "Token mismatch · request not sent");
      global.RkaViews.setCommandState("Confirmation token did not match");
      return;
    }
    var request = confirmation;
    dialogBusy = true;
    global.RkaViews.setDialogBusy(true);
    global.RkaViews.setConfirmationState("busy", "Applying protected action");
    void runAction({
      action: request.action, button: confirmationSubmit, candidate: request.candidate,
      confirmation: request.token, network: null
    }).then(function (outcome) {
      confirmation = null;
      dialogBusy = false;
      global.RkaViews.setDialogBusy(false);
      global.RkaViews.completeConfirmation(outcome);
    });
  });

  confirmationCancel.addEventListener("click", function () {
    if (dialogBusy) return;
    confirmation = null;
    global.RkaViews.closeConfirmation();
  });
  dialog.addEventListener("cancel", function (event) {
    if (dialogBusy) event.preventDefault();
    else confirmation = null;
  });
  dialog.addEventListener("close", function () {
    global.RkaViews.restoreFocus(focusAction, focusCandidate);
    focusAction = "";
    focusCandidate = "";
  });

  void (async function () {
    global.RkaViews.setBusy(true);
    await openSession();
    await requestAction({ action: "status", candidate: "", confirmation: "", network: null });
    global.RkaViews.setCommandState("Status refreshed");
    global.RkaViews.setProfileAvailability(false, false);
    global.RkaViews.setBusy(false);
  })().catch(function (error) {
    locked = true;
    global.RkaViews.setCommandState("WebUI unavailable");
    global.RkaFeedback.notice("WebUI unavailable", message(error), "error");
  });
})(globalThis);
