(function (global) {
  "use strict";

  var CONTROL = "/data/adb/modules/tricky_store/rka-control.sh";
  var NONCE = /^[0-9a-f]{32}$/;
  var CANDIDATE = /^[A-Za-z0-9_-]{1,64}$/;
  var STATUS = /^[A-Z][A-Z0-9_]*$/;
  var NUMBER_OR_NA = /^(?:[0-9]{1,16}|NOT_APPLICABLE)$/;
  var IPV4_OR_UNAVAILABLE = /^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|UNAVAILABLE)$/;
  var displayed = Object.freeze([
    "role", "phone_role", "runtime", "pairing", "direct_readiness",
    "rkp_provisioning", "synthetic_lease", "lease_valid_until_millis",
    "profile_epoch", "direct_profile", "diagnostic", "sentinel",
    "lease_epoch", "lease_next", "quarantine_count"
  ]);
  var labels = Object.freeze({
    ACTIVE: "Active", CANDIDATE: "Candidate", DIAGNOSTIC_ONLY: "Diagnostic only",
    DIRECT_NETWORK: "Direct network", DISABLED: "Disabled", DONOR: "Donor",
    EMPTY: "Empty", FAILED_CRASH_CAP: "Stopped · crash limit reached", INERT: "Inert",
    LIVE: "Live", LOCAL: "Local", LOCAL_LEGACY: "Local · legacy",
    NOT_APPLICABLE: "Not applicable", NOT_READY: "Not ready", PAIRED: "Paired",
    PENDING: "Pending", PHONE_A_DONOR: "Phone A · donor",
    PHONE_B_CANDIDATE: "Phone B · candidate", PROVISIONED: "Provisioned",
    QUARANTINED_AMBIGUOUS_MUTATION: "Quarantined · ambiguous mutation",
    READY: "Ready", RUNNING: "Running", STARTING: "Starting", STOPPING: "Stopping", STOPPED: "Stopped",
    UNAVAILABLE: "Unavailable", UNPAIRED: "Unpaired"
  });
  var fieldLabels = Object.freeze({
    role: "Module role", phone_role: "Phone role", runtime: "Runtime",
    pairing: "Pairing", direct_readiness: "Direct connection",
    rkp_provisioning: "Remote key provisioning", synthetic_lease: "Synthetic lease",
    lease_valid_until_millis: "Lease valid until", profile_epoch: "Profile revision",
    direct_profile: "Connection profile", diagnostic: "Diagnostic mode",
    sentinel: "Boot continuity", lease_epoch: "Current lease revision",
    lease_next: "Next lease slot", quarantine_count: "Quarantined mutations"
  });
  var fieldRules = Object.freeze({
    role: /^(?:LOCAL|DONOR|CANDIDATE|DISABLED)$/,
    phone_role: STATUS, runtime: STATUS, pairing: STATUS, direct_readiness: STATUS,
    rkp_provisioning: STATUS, synthetic_lease: STATUS, direct_profile: STATUS,
    diagnostic: STATUS, sentinel: STATUS, lease_next: /^(?:EMPTY|STAGED_[0-9]+)$/,
    profile_epoch: /^[0-9]{1,16}$/, lease_epoch: NUMBER_OR_NA,
    lease_valid_until_millis: NUMBER_OR_NA, quarantine_count: /^[0-9]{1,4}$/,
    network_peer_ip: IPV4_OR_UNAVAILABLE, network_local_ip: IPV4_OR_UNAVAILABLE,
    network_port: /^37373$/, nonce: NONCE, next_nonce: NONCE,
    confirmation_token: NONCE, confirmation_action: /^[a-z0-9-]{1,48}$/,
    candidate_id: CANDIDATE
  });
  var healthyValues = Object.freeze({
    direct_profile: "DIRECT_NETWORK", direct_readiness: "READY", pairing: "PAIRED",
    rkp_provisioning: "PROVISIONED", runtime: "RUNNING", sentinel: "LIVE",
    synthetic_lease: "ACTIVE"
  });
  var actions = Object.freeze({
    status: action("status", "Refreshing…", "Refreshing status", "Status refreshed", false, true),
    "role-donor": action("role-donor", "Assigning…", "Assigning donor role", "Donor role assigned", true),
    "role-candidate": action("role-candidate", "Assigning…", "Assigning candidate role", "Candidate role assigned", true),
    "profile-validate": action("profile-validate", "Validating…", "Validating profile", "Profile validated", true),
    "profile-apply": action("profile-apply", "Applying…", "Applying profile", "Profile applied", true),
    "network-save": action("network-save", "Saving…", "Saving network settings", "Network settings saved", true),
    "pair-direct": action("pair-direct", "Requesting…", "Requesting direct pairing", "Pairing requested", true, true),
    "rotate-pairing": action("rotate-pairing", "Requesting…", "Requesting pairing rotation", "Pairing rotation requested", true),
    "provision-rkp": action("provision-rkp", "Preparing…", "Preparing candidate-scoped donor RKP provisioning", "Candidate-scoped donor RKP provisioned", true, true),
    "renew-synthetic-lease": action("renew-synthetic-lease", "Preparing…", "Preparing candidate lease", "Candidate lease renewed", true, true),
    "rotate-attestation-roots": action("rotate-attestation-roots", "Preparing…", "Preparing root rotation", "Attestation roots rotated", true),
    start: action("start", "Starting…", "Starting runtime", "Runtime started", true),
    stop: action("stop", "Stopping…", "Stopping runtime", "Runtime stopped", true),
    "recover-keystore2": action("recover-keystore2", "Preparing…", "Preparing KeyStore2 recovery", "KeyStore2 recovered", true),
    "recover-rkpd": action("recover-rkpd", "Preparing…", "Preparing RKPD recovery", "RKPD recovered", true),
    "export-audit": action("export-audit", "Exporting…", "Exporting audit", "Audit export ready", true),
    "export-evidence": action("export-evidence", "Exporting…", "Exporting redacted evidence", "Evidence export ready", true),
    cleanup: action("cleanup", "Preparing…", "Preparing runtime cleanup", "Runtime state cleared", true),
    quarantine: action("quarantine", "Refreshing…", "Reading quarantine", "Quarantine refreshed", false)
  });

  function action(shell, pendingButton, pending, success, activity, candidate) {
    return Object.freeze({
      shell: shell, pendingButton: pendingButton, pending: pending, success: success,
      activity: activity, candidate: candidate === true, mutation: activity === true
    });
  }

  function own(object, key) {
    return Object.prototype.hasOwnProperty.call(object, key);
  }

  function getAction(name, profileRole) {
    if (!own(actions, name)) throw new Error("WebUI action was rejected");
    var selected = actions[name];
    if (name !== "profile-validate" && name !== "profile-apply") return selected;
    if (profileRole !== "DONOR" && profileRole !== "CANDIDATE") {
      throw new Error("Select a valid profile first");
    }
    return action(
      selected.shell + "-" + profileRole.toLowerCase(), selected.pendingButton,
      selected.pending, selected.success, selected.activity, selected.candidate
    );
  }

  function parseIpv4(input) {
    var parts = String(input).split(".");
    if (parts.length !== 4) throw new Error("Enter a valid IPv4 address");
    var parsed = [];
    for (var index = 0; index < parts.length; index += 1) {
      if (!/^[0-9]{1,3}$/.test(parts[index])) throw new Error("Enter a valid IPv4 address");
      var octet = Number(parts[index]);
      if (!Number.isInteger(octet) || octet > 255) throw new Error("Enter a valid IPv4 address");
      parsed.push(String(octet));
    }
    return parsed.join(".");
  }

  function addField(target, name, value) {
    if (!own(fieldRules, name)) return;
    if (!fieldRules[name].test(value) || target.has(name)) {
      throw new Error("WebUI status response was invalid");
    }
    target.set(name, value);
  }

  function parseOutput(stdout) {
    var text = String(stdout);
    if (text.length > 32768 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text)) {
      throw new Error("WebUI status response was invalid");
    }
    var values = new Map();
    var candidates = [];
    var candidateIds = new Set();
    var current = null;
    var lines = text.split("\n");
    for (var index = 0; index < lines.length; index += 1) {
      var line = lines[index];
      if (line.length > 1024) throw new Error("WebUI status response was invalid");
      var separator = line.indexOf("=");
      if (separator <= 0) continue;
      var name = line.slice(0, separator);
      var value = line.slice(separator + 1);
      if (name === "candidate_begin") {
        if (current !== null || !CANDIDATE.test(value) || candidateIds.has(value)) {
          throw new Error("Candidate status block was invalid");
        }
        current = new Map();
        current.set("candidate_begin", value);
        candidateIds.add(value);
      } else if (name === "candidate_end") {
        if (current === null || current.get("candidate_begin") !== value || current.get("candidate_id") !== value) {
          throw new Error("Candidate status block was invalid");
        }
        candidates.push(current);
        current = null;
      } else {
        if (name === "candidate_id" && current === null) throw new Error("Candidate status block was invalid");
        addField(current === null ? values : current, name, value);
      }
    }
    if (current !== null) throw new Error("Candidate status block was incomplete");
    if (candidates.length === 0 && values.has("role")) candidates.push(values);
    return { values: values, candidates: candidates };
  }

  function checkedResponse(value) {
    if (value === null || typeof value !== "object") throw new Error("WebUI bridge response was malformed");
    var errno = value.errno;
    if (typeof errno === "string" && /^(?:0|[1-9][0-9]{0,2})$/.test(errno)) errno = Number(errno);
    if (!Number.isSafeInteger(errno) || errno < 0 || errno > 255 || typeof value.stdout !== "string") {
      throw new Error("WebUI bridge response was malformed");
    }
    return { errno: errno, stdout: value.stdout, stderr: typeof value.stderr === "string" ? value.stderr : "" };
  }

  function buildCommand(request) {
    var selected = getAction(request.action, request.profileRole);
    if (!NONCE.test(request.nonce)) throw new Error("WebUI session was rejected");
    var command = CONTROL + " webui " + selected.shell + " " + request.nonce;
    if (request.action === "network-save") {
      var peer = parseIpv4(request.network.peer);
      var local = parseIpv4(request.network.local);
      command += " " + peer + "," + local + ",37373";
    } else if (request.confirmation !== "") {
      if (!NONCE.test(request.confirmation)) throw new Error("Confirmation token was invalid");
      command += " " + request.confirmation;
    }
    if (request.candidate !== "") {
      if (!selected.candidate || !CANDIDATE.test(request.candidate)) throw new Error("Candidate selector was invalid");
      command += " --candidate " + request.candidate;
    }
    return { command: command, metadata: selected };
  }

  function readable(name, value) {
    if (name === "lease_valid_until_millis" && /^[0-9]{1,16}$/.test(value)) {
      var millis = leaseMillis(value);
      return millis === null ? "Unavailable" : new Date(millis).toLocaleString();
    }
    if (/^STAGED_[0-9]+$/.test(value)) return "Staged · epoch " + value.slice(7);
    return own(labels, value) ? labels[value] : value;
  }

  function leaseMillis(value) {
    if (!/^[0-9]{1,16}$/.test(value)) return null;
    var millis = Number(value);
    if (!Number.isSafeInteger(millis) || Number.isNaN(new Date(millis).valueOf())) return null;
    return millis;
  }

  function health(name, value, values) {
    if (name === "role") return value === "DISABLED" ? "degraded" : "neutral";
    if (name === "lease_valid_until_millis") {
      if (value === "NOT_APPLICABLE") return "neutral";
      var millis = leaseMillis(value);
      return millis !== null && millis > Date.now() ? "healthy" : "degraded";
    }
    if (name === "quarantine_count") return value === "0" ? "healthy" : "degraded";
    if (name === "lease_next") return "neutral";
    if (value === "NOT_APPLICABLE" || value === "PENDING") return "neutral";
    if (!own(healthyValues, name)) return "neutral";
    return healthyValues[name] === value ? "healthy" : "degraded";
  }

  function sanitizeDetail(stderr, errno) {
    var detail = String(stderr).slice(0, 4096)
      .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "")
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
      .replace(/-----BEGIN[^\n]*-----[\s\S]*?-----END[^\n]*-----/g, "[redacted]")
      .replace(/\b[0-9a-fA-F]{32,}\b/g, "[redacted]")
      .replace(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g, "[redacted]");
    var lines = detail.split("\n").filter(function (line) { return line.trim() !== ""; }).slice(0, 3);
    detail = lines.join(" · ").slice(0, 480);
    return detail === "" ? "Request failed with exit code " + errno : detail;
  }

  function parseProfile(text) {
    var value = JSON.parse(text);
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Profile file was invalid");
    var keys = Object.keys(value);
    if (keys.length !== 4 || value.version !== 1 ||
        (value.role !== "DONOR" && value.role !== "CANDIDATE") ||
        !Number.isSafeInteger(value.profile_epoch) || value.profile_epoch < 0 ||
        value.transport !== "DIRECT_NETWORK") {
      throw new Error("Profile file was invalid");
    }
    return value.role;
  }

  global.RkaModel = Object.freeze({
    CONTROL: CONTROL, displayed: displayed, buildCommand: buildCommand,
    checkedResponse: checkedResponse, fieldLabel: function (name) { return fieldLabels[name]; },
    getAction: getAction, health: health, parseIpv4: parseIpv4,
    parseOutput: parseOutput, parseProfile: parseProfile, readable: readable,
    sanitizeDetail: sanitizeDetail
  });
})(globalThis);
