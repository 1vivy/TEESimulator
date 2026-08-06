(function (global) {
  "use strict";

  var busy = false;
  var currentRole = "";
  var candidateStates = new Map();
  var statusList = required("#rka-status-list");
  var operation = required("#command-state");
  var leaseTemplate = required("#candidate-lease-action");
  var provisionTemplate = required("#candidate-provision-action");
  var peerInput = required("#network-peer-ip");
  var localInput = required("#network-local-ip");
  var networkSubmit = required("#network-submit");
  var networkScopeMessage = required("#network-scope-message");
  var peerError = required("#network-peer-error");
  var localError = required("#network-local-error");
  var dialog = required("#confirmation-dialog");
  var dialogHeading = required("#confirmation-heading");
  var dialogInstructions = required("#confirmation-instructions");
  var dialogState = required("#confirmation-state");
  var tokenOutput = required("#confirmation-token");
  var confirmationInput = required("#confirmation-input");
  var confirmationField = required("#confirmation-field");
  var confirmationSubmit = required("#confirmation-submit");
  var confirmationCancel = required("#confirmation-cancel");

  function required(selector) {
    var element = document.querySelector(selector);
    if (!(element instanceof HTMLElement)) throw new Error("WebUI markup was incomplete");
    return element;
  }

  function removeChildren(element) {
    while (element.firstChild !== null) element.removeChild(element.firstChild);
  }

  function setAvailable(control, available) {
    control.dataset.available = available ? "true" : "false";
    control.disabled = busy || !available;
  }

  function refreshAvailability() {
    var controls = document.querySelectorAll("[data-privileged]");
    for (var index = 0; index < controls.length; index += 1) {
      var control = controls[index];
      if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement) {
        control.disabled = busy || control.dataset.available === "false";
      }
    }
    var provisions = document.querySelectorAll('button[data-action="provision-rkp"]');
    for (var provisionIndex = 0; provisionIndex < provisions.length; provisionIndex += 1) {
      var provision = provisions[provisionIndex];
      if (!(provision instanceof HTMLButtonElement)) continue;
      var provisionCandidate = provision.dataset.candidateId || "";
      var provisionState = candidateStates.get(provisionCandidate);
      var provisionReady = provisionState instanceof Map &&
        provisionState.get("role") === "DONOR" &&
        provisionState.get("direct_readiness") === "READY";
      setAvailable(provision, provisionReady);
    }
    var renewals = statusList.querySelectorAll('button[data-action="renew-synthetic-lease"]');
    for (var renewalIndex = 0; renewalIndex < renewals.length; renewalIndex += 1) {
      var renew = renewals[renewalIndex];
      if (!(renew instanceof HTMLButtonElement)) continue;
      var candidateId = typeof renew.dataset.candidateId === "string" ? renew.dataset.candidateId : "";
      var state = candidateStates.get(candidateId);
      var ready = state instanceof Map && state.get("role") === "CANDIDATE" &&
        state.get("direct_readiness") === "READY" && state.get("lease_next") === "EMPTY" &&
        (state.get("synthetic_lease") === "NOT_READY" || state.get("synthetic_lease") === "ACTIVE");
      setAvailable(renew, ready);
    }
  }

  function renderNetwork(values) {
    if (!(values instanceof Map)) return;
    var peer = values.get("network_peer_ip");
    var local = values.get("network_local_ip");
    if (peer !== undefined && peer !== "UNAVAILABLE" &&
        peerInput.dataset.dirty !== "true" && document.activeElement !== peerInput) {
      peerInput.value = peer;
    }
    if (local !== undefined && local !== "UNAVAILABLE" &&
        localInput.dataset.dirty !== "true" && document.activeElement !== localInput) {
      localInput.value = local;
    }
  }

  function setNetworkEditable(editable) {
    peerInput.disabled = !editable;
    localInput.disabled = !editable;
    setAvailable(networkSubmit, editable);
    networkScopeMessage.textContent = editable ? "" :
      "Multi-candidate donor addresses are managed per candidate through the host CLI.";
  }

  function renderStatus(candidates) {
    currentRole = candidates.length > 0 ? candidates[0].get("role") || "" : "";
    candidateStates.clear();
    removeChildren(statusList);
    for (var candidateIndex = 0; candidateIndex < candidates.length; candidateIndex += 1) {
      var values = candidates[candidateIndex];
      var candidateId = values.get("candidate_id") || "";
      candidateStates.set(candidateId, values);
      var headingId = "candidate-status-heading-" + candidateIndex;
      var card = document.createElement("section");
      card.className = "candidate-status-card";
      card.dataset.candidateId = candidateId;
      card.setAttribute("aria-labelledby", headingId);
      var heading = document.createElement("div");
      heading.className = "candidate-card-heading";
      var eyebrow = document.createElement("p");
      eyebrow.className = "eyebrow";
      eyebrow.textContent = candidateId === "" ? "Current device" : "Paired candidate";
      var title = document.createElement("h3");
      title.id = headingId;
      title.textContent = candidateId === "" ? "This phone" : candidateId;
      heading.appendChild(eyebrow);
      heading.appendChild(title);
      var status = document.createElement("dl");
      status.className = "status-grid";
      for (var fieldIndex = 0; fieldIndex < global.RkaModel.displayed.length; fieldIndex += 1) {
        var name = global.RkaModel.displayed[fieldIndex];
        var value = values.get(name) || "UNAVAILABLE";
        var box = document.createElement("div");
        var term = document.createElement("dt");
        var detail = document.createElement("dd");
        term.textContent = global.RkaModel.fieldLabel(name);
        detail.textContent = global.RkaModel.readable(name, value);
        detail.dataset.statusField = name;
        detail.dataset.health = global.RkaModel.health(name, value, values);
        box.appendChild(term);
        box.appendChild(detail);
        status.appendChild(box);
      }
      card.appendChild(heading);
      card.appendChild(status);
      if (candidateId === "" && values.get("role") === "CANDIDATE" &&
          leaseTemplate instanceof HTMLTemplateElement) {
        var cloned = leaseTemplate.content.firstElementChild;
        var renew = cloned === null ? null : cloned.cloneNode(true);
        if (renew instanceof HTMLButtonElement) {
          card.appendChild(renew);
        }
      } else if (candidateId !== "" && values.get("role") === "DONOR" &&
          provisionTemplate instanceof HTMLTemplateElement) {
        var provisioned = provisionTemplate.content.firstElementChild;
        var candidateProvision = provisioned === null ? null : provisioned.cloneNode(true);
        if (candidateProvision instanceof HTMLButtonElement) {
          candidateProvision.dataset.candidateId = candidateId;
          candidateProvision.setAttribute("aria-label", "Provision candidate RKP for " + candidateId);
          card.appendChild(candidateProvision);
        }
      }
      statusList.appendChild(card);
    }
    if (candidates.length > 0) renderNetwork(candidates[0]);
    setNetworkEditable(candidates.every(function (values) { return !values.has("candidate_id"); }));
    refreshAvailability();
  }

  function setBusy(nextBusy) {
    busy = nextBusy;
    document.body.dataset.busy = nextBusy ? "true" : "false";
    refreshAvailability();
  }

  function showNetworkErrors(peerMessage, localMessage) {
    peerError.textContent = peerMessage;
    localError.textContent = localMessage;
    if (peerMessage === "") peerInput.removeAttribute("aria-invalid");
    else peerInput.setAttribute("aria-invalid", "true");
    if (localMessage === "") localInput.removeAttribute("aria-invalid");
    else localInput.setAttribute("aria-invalid", "true");
  }

  function markNetworkDirty(input) {
    if (input === peerInput || input === localInput) input.dataset.dirty = "true";
  }

  function clearNetworkDirty() {
    peerInput.dataset.dirty = "false";
    localInput.dataset.dirty = "false";
  }

  function setProfileAvailability(loaded, validated) {
    var validate = document.querySelector('[data-action="profile-validate"]');
    var apply = document.querySelector('[data-action="profile-apply"]');
    if (validate instanceof HTMLButtonElement) setAvailable(validate, loaded);
    if (apply instanceof HTMLButtonElement) setAvailable(apply, validated);
  }

  function openConfirmation(value) {
    dialogHeading.textContent = "Confirm exact action";
    dialogInstructions.hidden = false;
    tokenOutput.hidden = false;
    confirmationField.hidden = false;
    confirmationCancel.hidden = false;
    tokenOutput.textContent = value;
    confirmationInput.value = "";
    confirmationInput.disabled = false;
    confirmationSubmit.textContent = "Confirm action";
    confirmationSubmit.disabled = false;
    confirmationCancel.disabled = false;
    setConfirmationState("awaiting-token", "Awaiting one-time token");
    dialog.showModal();
    confirmationInput.focus();
  }

  function setConfirmationState(state, message) {
    dialog.dataset.state = state;
    dialogState.textContent = message;
    dialogInstructions.hidden = state === "accepted" || state === "not-sent" || state === "unknown";
    if (state === "mismatch") confirmationInput.setAttribute("aria-invalid", "true");
    else confirmationInput.removeAttribute("aria-invalid");
  }

  function setDialogBusy(nextBusy) {
    confirmationInput.disabled = nextBusy;
    confirmationSubmit.disabled = nextBusy;
    confirmationCancel.disabled = nextBusy;
  }

  function completeConfirmation(outcome) {
    var headings = { accepted: "Action accepted", "not-sent": "Request not sent", unknown: "Outcome unknown" };
    var messages = {
      accepted: "Protected action accepted",
      "not-sent": "Protected action was not sent",
      unknown: "Protected action outcome unknown · reopen this page"
    };
    tokenOutput.textContent = "";
    tokenOutput.hidden = true;
    confirmationInput.value = "";
    confirmationField.hidden = true;
    confirmationCancel.hidden = true;
    confirmationSubmit.textContent = "Close";
    dialogHeading.textContent = headings[outcome];
    setConfirmationState(outcome, messages[outcome]);
  }

  function restoreFocus(action, candidate) {
    var controls = document.querySelectorAll("button[data-action]");
    for (var index = 0; index < controls.length; index += 1) {
      var control = controls[index];
      if (control instanceof HTMLButtonElement && control.dataset.action === action &&
          (control.dataset.candidateId || "") === candidate) {
        control.focus();
        return;
      }
    }
  }

  global.RkaViews = Object.freeze({
    clearNetworkDirty: clearNetworkDirty,
    closeConfirmation: function () { dialog.close(); },
    completeConfirmation: completeConfirmation,
    confirmationInput: function () { return confirmationInput.value; },
    currentConfirmationState: function () { return dialog.dataset.state || ""; },
    markNetworkDirty: markNetworkDirty,
    networkValues: function () { return { peer: peerInput.value, local: localInput.value }; },
    openConfirmation: openConfirmation, refreshAvailability: refreshAvailability,
    renderStatus: renderStatus, restoreFocus: restoreFocus, setBusy: setBusy,
    setCommandState: function (message) { operation.textContent = message; },
    setConfirmationState: setConfirmationState, setDialogBusy: setDialogBusy,
    setProfileAvailability: setProfileAvailability, showNetworkErrors: showNetworkErrors
  });
})(globalThis);
