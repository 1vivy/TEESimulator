import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { basename, isAbsolute, join, relative, resolve, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";

const SOURCE_PATHS = Object.freeze([
  "app/build.gradle.kts", "app/proguard-rules.pro",
  "app/src/main/java/org/matrix/TEESimulator/rka/trust/AgentPgpVerifier.kt",
  "app/src/test/java/org/matrix/TEESimulator/rka/trust/AgentPgpVerifierTest.kt",
  "app/src/test/resources/rka/agent-pgp-valid-bundle.txt", "app/src/test/resources/rka/agent-pgp-valid-message.txt",
  "app/src/test/resources/rka/agent-pgp-valid-signature.pgp", "app/src/test/resources/rka/agent-pgp-wrong-signer-signature.pgp",
  "gradle/libs.versions.toml", "module/rka-agent-pgp-public.gpg", "module/rka-agent-pgp-verify",
  "module/rka-control.sh", "module/rka-paths.sh", "module/rka-runtime.manifest", "module/rka-supervisor.sh",
  "module/webroot/DESIGN.md", "module/webroot/app.js", "module/webroot/index.html", "module/webroot/style.css",
  "tests/fixtures/profile-candidate.json", "tests/test_rka_package.py", "tests/test_rka_webui.py",
  "tests/test_rka_webui_integration.py", "tests/webui_server.py", "webui-test/package-lock.json",
  "webui-test/package.json", "webui-test/playwright.config.ts", "webui-test/scripts/test-evidence-manifest.mjs",
  "webui-test/scripts/verify-browser.mjs", "webui-test/scripts/write-evidence-manifest.mjs", "webui-test/tests/live.spec.ts",
]);

const CAPTURES = Object.freeze([
  ["responsive-375", "task-26-webui-375.png"], ["responsive-768", "task-26-webui-768.png"],
  ["responsive-1280", "task-26-webui-1280.png"], ["hover", "task-26-webui-hover.png"],
  ["keyboard-focus", "task-26-webui-focus.png"], ["active", "task-26-webui-active.png"],
  ["failure-state", "task-26-failure-state.png"], ["confirmation-awaiting", "task-26-confirm-awaiting.png"],
  ["confirmation-mismatch", "task-26-confirm-mismatch.png"], ["confirmation-busy", "task-26-confirm-busy.png"],
  ["confirmation-accepted", "task-26-confirm-accepted.png"], ["confirmation-refused", "task-26-confirm-refused.png"],
]);

const REVIEWER_FILES = Object.freeze(["visual-review-a.txt", "visual-review-b.txt"]);
const BROWSER_RECEIPT = Object.freeze({
  browserVersion: "151.0.7922.34",
  executables: [
    { path: "chromium-1234/chrome-linux64/chrome", version: "Google Chrome for Testing 151.0.7922.34" },
    { path: "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell", version: "Google Chrome for Testing 151.0.7922.34" },
  ],
  packageVersion: "1.62.0",
  payloads: [
    { path: "chromium-1234/chrome-linux64/chrome", sha256: "0b20b130e7edd9dd51873be867761295fe0cfad490c2b9a64f95bd3cfc08fa71" },
    { path: "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell", sha256: "e11fc9ce65c96313476f7ee9844b6fb6a9220fb048693cfe9eee00acf4170a9f" },
    { path: "ffmpeg-1011/ffmpeg-linux", sha256: "460d44f3416005662f528d4b92e7b94ace924e8a0288106d3803b73c56eaadc8" },
  ],
  revision: "1234",
  verified: true,
});

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

function canonicalRoot(path, label) {
  const absolute = resolve(path);
  if (realpathSync(absolute) !== absolute) throw new ManifestError(`${label} is not canonical`);
  const entry = lstatSync(absolute);
  if (!entry.isDirectory() || entry.isSymbolicLink()) throw new ManifestError(`${label} is not a regular directory`);
  return absolute;
}

function regularFile(root, path, label) {
  const absolute = resolve(path);
  const fromRoot = relative(root, absolute);
  const escaped = fromRoot === "" || fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot);
  if (escaped) throw new ManifestError(`${label} escaped its root`);
  if (realpathSync(absolute) !== absolute) throw new ManifestError(`${label} is not canonical`);
  const entry = lstatSync(absolute);
  if (!entry.isFile() || entry.isSymbolicLink()) throw new ManifestError(`${label} is not a regular file`);
  return absolute;
}

function parseCanonicalJson(contents, label, pretty) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(contents));
  } catch (error) {
    throw new ManifestError(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
  const canonical = pretty ? `${JSON.stringify(value, null, 2)}\n` : `${JSON.stringify(value)}\n`;
  if (!contents.equals(Buffer.from(canonical))) {
    throw new ManifestError(`${label} is not canonical JSON`);
  }
  return value;
}

function requireEqual(actual, expected, label) {
  if (!isDeepStrictEqual(actual, expected)) throw new ManifestError(`${label} mismatch`);
}

function pngDimensions(contents) {
  const signature = contents.subarray(0, 8).toString("hex");
  if (signature !== "89504e470d0a1a0a" || contents.subarray(12, 16).toString("ascii") !== "IHDR") {
    throw new ManifestError("capture is not a PNG");
  }
  return { height: contents.readUInt32BE(20), width: contents.readUInt32BE(16) };
}

function sourceRecord(repository, path) {
  const absolute = regularFile(repository, join(repository, path), `source ${path}`);
  const contents = readFileSync(absolute);
  return {
    gitBlob: git(repository, "rev-parse", `HEAD:${path}`),
    mtimeNs: statSync(absolute, { bigint: true }).mtimeNs.toString(),
    path,
    sha256: digest(contents),
  };
}

function captureRecord(evidence, [stateId, filename]) {
  const absolute = regularFile(evidence, join(evidence, filename), `capture ${filename}`);
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

function browserReceiptRecord(evidence, suppliedPath) {
  const expectedPath = join(evidence, "browser-receipt.json");
  if (resolve(suppliedPath) !== expectedPath) {
    throw new ManifestError("browser receipt path is not fixed beneath evidence root");
  }
  const path = regularFile(evidence, expectedPath, "browser receipt");
  const bytes = readFileSync(path);
  const receipt = parseCanonicalJson(bytes, "browser receipt", false);
  requireEqual(receipt, BROWSER_RECEIPT, "browser receipt frozen fields");
  return { bytes, receipt };
}

function reconstructCaptureReceipt(repository, evidence, browserReceiptPath) {
  if (!trackedTreeIsClean(repository)) throw new ManifestError("tracked tree is not clean");
  const commit = git(repository, "rev-parse", "HEAD");
  if (!/^[0-9a-f]{40}$/.test(commit)) throw new ManifestError("commit is not canonical");
  const commitTimestampSeconds = Number(git(repository, "show", "-s", "--format=%ct", "HEAD"));
  if (!Number.isSafeInteger(commitTimestampSeconds) || commitTimestampSeconds <= 0) throw new ManifestError("commit timestamp is invalid");
  const sources = SOURCE_PATHS.map((path) => sourceRecord(repository, path));
  const expectedCaptureFiles = CAPTURES.map(([, filename]) => filename).toSorted();
  const actualCaptureFiles = readdirSync(evidence).filter((filename) => filename.endsWith(".png")).toSorted();
  requireEqual(actualCaptureFiles, expectedCaptureFiles, "capture file set");
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
  const browser = browserReceiptRecord(evidence, browserReceiptPath);
  return {
    browserReceipt: browser.receipt,
    browserReceiptSha256: digest(browser.bytes),
    captures,
    commit,
    commitTimestampSeconds,
    schema: 1,
    sourceMtimeMaximumNs: sourceMtimeMaximumNs.toString(),
    sources,
    trackedDiffCleanAfterCapture: trackedTreeIsClean(repository),
  };
}

function writeCaptureReceipt(repository, evidence, browserReceiptPath) {
  writeJson(
    join(evidence, "capture-receipt.json"),
    reconstructCaptureReceipt(repository, evidence, browserReceiptPath),
  );
}

function reviewerRecord(evidence, path, expectedFilename, captureMtimeMaximumNs) {
  const expectedPath = join(evidence, expectedFilename);
  if (resolve(path) !== expectedPath) throw new ManifestError("reviewer path is not fixed");
  const absolute = regularFile(evidence, expectedPath, `reviewer ${expectedFilename}`);
  const contents = readFileSync(absolute);
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(contents);
  } catch (error) {
    throw new ManifestError(`reviewer is not UTF-8: ${error.message}`);
  }
  const verdicts = text.match(/^VERDICT: .+$/gm) ?? [];
  if (verdicts.length !== 1 || text.trimEnd().split("\n").at(-1) !== "VERDICT: PASS") {
    throw new ManifestError("reviewer did not end with one PASS verdict");
  }
  const mtimeNs = statSync(absolute, { bigint: true }).mtimeNs;
  if (mtimeNs <= captureMtimeMaximumNs) throw new ManifestError("reviewer predates captures");
  return {
    filename: basename(absolute),
    mtimeNs: mtimeNs.toString(),
    sha256: digest(contents),
    verdict: "PASS",
  };
}

function writeFinalManifest(repository, evidence, reviewA, reviewB) {
  if (!trackedTreeIsClean(repository)) throw new ManifestError("tracked tree is not clean");
  const captureReceiptPath = regularFile(
    evidence,
    join(evidence, "capture-receipt.json"),
    "capture receipt",
  );
  const captureReceiptBytes = readFileSync(captureReceiptPath);
  const captureReceipt = parseCanonicalJson(captureReceiptBytes, "capture receipt", true);
  const expectedCaptureReceipt = reconstructCaptureReceipt(
    repository,
    evidence,
    join(evidence, "browser-receipt.json"),
  );
  requireEqual(captureReceipt, expectedCaptureReceipt, "capture receipt reconstruction");
  const captureMtimeMaximumNs = expectedCaptureReceipt.captures.reduce(
    (maximum, capture) => (BigInt(capture.mtimeNs) > maximum ? BigInt(capture.mtimeNs) : maximum),
    0n,
  );
  const expectedManifest = {
    captureReceipt: expectedCaptureReceipt,
    captureReceiptSha256: digest(captureReceiptBytes),
    reviewers: [
      reviewerRecord(evidence, reviewA, REVIEWER_FILES[0], captureMtimeMaximumNs),
      reviewerRecord(evidence, reviewB, REVIEWER_FILES[1], captureMtimeMaximumNs),
    ],
    schema: 1,
    trackedDiffCleanAtManifest: trackedTreeIsClean(repository),
  };
  const manifestPath = join(evidence, "evidence-manifest.json");
  if (existsSync(manifestPath)) {
    const regularManifestPath = regularFile(evidence, manifestPath, "evidence manifest");
    const existingBytes = readFileSync(regularManifestPath);
    const existing = parseCanonicalJson(existingBytes, "evidence manifest", true);
    requireEqual(existing, expectedManifest, "existing evidence manifest reconstruction");
  } else {
    writeJson(manifestPath, expectedManifest);
  }
}

const [mode, repositoryArgument, evidenceArgument, ...rest] = process.argv.slice(2);
if (mode === undefined || repositoryArgument === undefined || evidenceArgument === undefined) {
  throw new ManifestError("expected mode, repository, and evidence directory");
}
const repository = canonicalRoot(repositoryArgument, "repository");
const evidence = canonicalRoot(evidenceArgument, "evidence");
if (mode === "capture" && rest.length === 1) {
  writeCaptureReceipt(repository, evidence, resolve(rest[0]));
} else if (mode === "final" && rest.length === 2) {
  writeFinalManifest(repository, evidence, resolve(rest[0]), resolve(rest[1]));
} else {
  throw new ManifestError("invalid evidence manifest invocation");
}
