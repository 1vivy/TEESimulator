(function (global) {
  "use strict";

  var toastRoot;
  var activityRoot;
  var toastSequence = 0;
  var originalLabels = new Map();

  function initialize(toasts, activity) {
    toastRoot = toasts;
    activityRoot = activity;
  }

  function trimToasts() {
    while (toastRoot.children.length > 1) toastRoot.removeChild(toastRoot.firstElementChild);
  }

  function createToast(title, detail, state) {
    toastSequence += 1;
    var item = document.createElement("li");
    item.className = "toast toast-" + state;
    item.dataset.toastId = String(toastSequence);
    var marker = document.createElement("span");
    marker.className = "toast-marker";
    marker.setAttribute("aria-hidden", "true");
    var content = document.createElement("div");
    content.className = "toast-content";
    var heading = document.createElement("strong");
    heading.className = "toast-title";
    heading.textContent = title;
    var message = document.createElement("p");
    message.className = "toast-detail";
    message.textContent = detail;
    content.appendChild(heading);
    content.appendChild(message);
    item.appendChild(marker);
    item.appendChild(content);
    toastRoot.appendChild(item);
    trimToasts();
    return item;
  }

  function updateToast(item, title, detail, state) {
    item.className = "toast toast-" + state;
    item.querySelector(".toast-title").textContent = title;
    item.querySelector(".toast-detail").textContent = detail;
    if (state !== "pending" && item.querySelector("button") === null) {
      var dismiss = document.createElement("button");
      dismiss.type = "button";
      dismiss.className = "toast-dismiss";
      dismiss.setAttribute("aria-label", "Dismiss notification");
      dismiss.textContent = "Close";
      dismiss.addEventListener("click", function () { removeToast(item); });
      item.appendChild(dismiss);
      global.setTimeout(function () { removeToast(item); }, 6000);
    }
  }

  function removeToast(item) {
    if (item.parentNode === toastRoot) toastRoot.removeChild(item);
  }

  function begin(button, metadata) {
    if (button instanceof HTMLButtonElement) {
      originalLabels.set(button, button.textContent);
      button.textContent = metadata.pendingButton;
      button.setAttribute("aria-busy", "true");
    }
    return createToast(metadata.pending, "Waiting for the device", "pending");
  }

  function settleButton(button) {
    if (!(button instanceof HTMLButtonElement)) return;
    var original = originalLabels.get(button);
    if (typeof original === "string") button.textContent = original;
    originalLabels.delete(button);
    button.setAttribute("aria-busy", "false");
  }

  function addActivity(title, outcome) {
    var item = document.createElement("li");
    var action = document.createElement("strong");
    var result = document.createElement("span");
    action.textContent = title;
    result.textContent = outcome;
    item.dataset.health = outcome === "Completed" ? "healthy" : outcome === "Unknown" ? "neutral" : "degraded";
    item.appendChild(action);
    item.appendChild(result);
    activityRoot.insertBefore(item, activityRoot.firstChild);
    while (activityRoot.children.length > 8) activityRoot.removeChild(activityRoot.lastElementChild);
  }

  function notice(title, detail, state) {
    var item = createToast(title, detail, state);
    updateToast(item, title, detail, state);
  }

  global.RkaFeedback = Object.freeze({
    addActivity: addActivity,
    begin: begin,
    initialize: initialize,
    notice: notice,
    settleButton: settleButton,
    updateToast: updateToast
  });
})(globalThis);
