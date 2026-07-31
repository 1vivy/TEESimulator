import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";

const SOURCE_PATHS = Object.freeze([
  "app/build.gradle.kts",
  "app/proguard-rules.pro",
  "app/src/main/java/org/matrix/TEESimulator/rka/trust/AgentPgpVerifier.kt",
  "app/src/test/java/org/matrix/TEESimulator/rka/trust/AgentPgpVerifierTest.kt",
  "app/src/test/resources/rka/agent-pgp-valid-bundle.txt",
  "app/src/test/resources/rka/agent-pgp-valid-message.txt",
  "app/src/test/resources/rka/agent-pgp-valid-signature.pgp",
  "app/src/test/resources/rka/agent-pgp-wrong-signer-signature.pgp",
  "gradle/libs.versions.toml",
  "module/rka-agent-pgp-public.gpg",
  "module/rka-agent-pgp-verify",
  "module/rka-control.sh",
  "module/rka-paths.sh",
  "module/rka-runtime.manifest",
  "module/rka-supervisor.sh",
  "module/webroot/DESIGN.md",
  "module/webroot/app.js",
  "module/webroot/index.html",
  "module/webroot/style.css",
  "tests/fixtures/profile-candidate.json",
  "tests/test_rka_package.py",
  "tests/test_rka_webui.py",
  "tests/test_rka_webui_integration.py",
  "tests/webui_server.py",
  "webui-test/package-lock.json",
  "webui-test/package.json",
  "webui-test/playwright.config.ts",
  "webui-test/scripts/verify-browser.mjs",
  "webui-test/scripts/write-evidence-manifest.mjs",
  "webui-test/tests/live.spec.ts",
]);

const CAPTURES = Object.freeze([
  ["responsive-375", "task-26-webui-375.png"],
  ["responsive-768", "task-26-webui-768.png"],
  ["responsive-1280", "task-26-webui-1280.png"],
  ["hover", "task-26-webui-hover.png"],
  ["keyboard-focus", "task-26-webui-focus.png"],
  ["active", "task-26-webui-active.png"],
  ["failure-state", "task-26-failure-state.png"],
  ["confirmation-awaiting", "task-26-confirm-awaiting.png"],
  ["confirmation-mismatch", "task-26-confirm-mismatch.png"],
  ["confirmation-busy", "task-26-confirm-busy.png"],
  ["confirmation-accepted", "task-26-confirm-accepted.png"],
  ["confirmation-refused", "task-26-confirm-refused.png"],
]);

class ManifestError extends Error {}

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function git(repository, ...gitArguments) {
  return execFileSync("git", ["-C", repository, ...gitArguments], { encoding: "utf8" }).trim();
}

function trackedTreeIsClean(repository) {
  return (
    git(repository, "diff", "--name-only") === "" &&
    git(repository, "diff", "--cached", "--name-only") === ""
  );
}

function pngDimensions(contents) {
  const signature = contents.subarray(0, 8).toString("hex");
  if (signature !== "89504e470d0a1a0a" || contents.subarray(12, 16).toString("ascii") !== "IHDR") {
    throw new ManifestError("capture is not a PNG");
  }
  return { height: contents.readUInt32BE(20), width: contents.readUInt32BE(16) };
}

function sourceRecord(repository, path) {
  const absolute = join(repository, path);
  const contents = readFileSync(absolute);
  return {
    gitBlob: git(repository, "rev-parse", `HEAD:${path}`),
    mtimeNs: statSync(absolute, { bigint: true }).mtimeNs.toString(),
    path,
    sha256: digest(contents),
  };
}

function captureRecord(evidence, [stateId, filename]) {
  const absolute = join(evidence, filename);
  const contents = readFileSync(absolute);
  return {
    filename,
    ...pngDimensions(contents),
    mtimeNs: statSync(absolute, { bigint: true }).mtimeNs.toString(),
    sha256: digest(contents),
    stateId,
  };
}

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function writeCaptureReceipt(repository, evidence, browserReceiptPath) {
  if (!trackedTreeIsClean(repository)) throw new ManifestError("tracked tree is not clean");
  const commit = git(repository, "rev-parse", "HEAD");
  const commitTimestampSeconds = Number(git(repository, "show", "-s", "--format=%ct", "HEAD"));
  const sources = SOURCE_PATHS.map((path) => sourceRecord(repository, path));
  const captures = CAPTURES.map((capture) => captureRecord(evidence, capture));
  const sourceMtimeMaximumNs = sources.reduce(
    (maximum, source) => (BigInt(source.mtimeNs) > maximum ? BigInt(source.mtimeNs) : maximum),
    0n,
  );
  const commitNs = BigInt(commitTimestampSeconds) * 1_000_000_000n;
  if (captures.some((capture) => BigInt(capture.mtimeNs) <= sourceMtimeMaximumNs)) {
    throw new ManifestError("capture predates source checkout");
  }
  if (captures.some((capture) => BigInt(capture.mtimeNs) <= commitNs)) {
    throw new ManifestError("capture predates commit");
  }
  const browserReceiptBytes = readFileSync(browserReceiptPath);
  const browserReceipt = JSON.parse(browserReceiptBytes.toString("utf8"));
  if (browserReceipt.verified !== true) throw new ManifestError("browser receipt is not verified");
  writeJson(join(evidence, "capture-receipt.json"), {
    browserReceipt,
    browserReceiptSha256: digest(browserReceiptBytes),
    captures,
    commit,
    commitTimestampSeconds,
    schema: 1,
    sourceMtimeMaximumNs: sourceMtimeMaximumNs.toString(),
    sources,
    trackedDiffCleanAfterCapture: trackedTreeIsClean(repository),
  });
}

function reviewerRecord(path) {
  const contents = readFileSync(path);
  const text = contents.toString("utf8");
  if (!/\bVERDICT:\s*PASS\b/.test(text)) throw new ManifestError("reviewer did not pass");
  return {
    filename: basename(path),
    mtimeNs: statSync(path, { bigint: true }).mtimeNs.toString(),
    sha256: digest(contents),
    verdict: "PASS",
  };
}

function writeFinalManifest(repository, evidence, reviewA, reviewB) {
  if (!trackedTreeIsClean(repository)) throw new ManifestError("tracked tree is not clean");
  const captureReceiptPath = join(evidence, "capture-receipt.json");
  const captureReceiptBytes = readFileSync(captureReceiptPath);
  const captureReceipt = JSON.parse(captureReceiptBytes.toString("utf8"));
  if (captureReceipt.commit !== git(repository, "rev-parse", "HEAD")) {
    throw new ManifestError("capture receipt commit drift");
  }
  writeJson(join(evidence, "evidence-manifest.json"), {
    captureReceipt,
    captureReceiptSha256: digest(captureReceiptBytes),
    reviewers: [reviewerRecord(reviewA), reviewerRecord(reviewB)],
    schema: 1,
    trackedDiffCleanAtManifest: trackedTreeIsClean(repository),
  });
}

const [mode, repositoryArgument, evidenceArgument, ...rest] = process.argv.slice(2);
if (mode === undefined || repositoryArgument === undefined || evidenceArgument === undefined) {
  throw new ManifestError("expected mode, repository, and evidence directory");
}
const repository = resolve(repositoryArgument);
const evidence = resolve(evidenceArgument);
if (mode === "capture" && rest.length === 1) {
  writeCaptureReceipt(repository, evidence, resolve(rest[0]));
} else if (mode === "final" && rest.length === 2) {
  writeFinalManifest(repository, evidence, resolve(rest[0]), resolve(rest[1]));
} else {
  throw new ManifestError("invalid evidence manifest invocation");
}
