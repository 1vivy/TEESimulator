import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { chromium } from "@playwright/test";

const repository = resolve(import.meta.dirname, "../..");
const evidence = resolve(process.argv[2] ?? "");
const sourcePaths = Object.freeze([
  "README.md",
  "app/src/main/java/org/matrix/TEESimulator/rka/bridge/DonorProvisioningRuntime.kt",
  "docs/RKA_BETA_GUIDE.md",
  "docs/RKA_BETA_RELEASE_NOTES.md",
  "module/rka-control.sh",
  "module/rka-supervisor.sh",
  "module/webroot/DESIGN.md",
  "module/webroot/app.js",
  "module/webroot/bridge.js",
  "module/webroot/components.css",
  "module/webroot/controls.css",
  "module/webroot/feedback.js",
  "module/webroot/index.html",
  "module/webroot/layout.css",
  "module/webroot/model.js",
  "module/webroot/profile.js",
  "module/webroot/tokens.css",
  "module/webroot/views.js",
  "rka-runtime/crates/rka-sidecar/src/direct_activation.rs",
  "rka-runtime/crates/rka-sidecar/src/direct_profile/loader.rs",
  "rka-runtime/crates/rka-sidecar/src/direct_session.rs",
  "rka-runtime/crates/rka-sidecar/src/direct_session_tests.rs",
  "tests/test_rka_control.py",
  "tests/test_rka_fail_closed.py",
  "tests/test_rka_runtime_evidence.py",
  "tests/test_rka_supervisor.py",
  "tests/test_rka_webui.py",
  "tests/test_rka_webui_integration.py",
  "tests/webui_browser_harness.mjs",
  "tests/webui_browser_support.mjs",
  "tests/webui_server.py",
  "tests/webui_server_state.py",
  "webui-test/package-lock.json",
  "webui-test/package.json",
  "webui-test/playwright.config.ts",
  "webui-test/tests/candidates.spec.ts",
  "webui-test/tests/fixtures.ts",
  "webui-test/tests/interactions.spec.ts",
  "webui-test/tests/live.spec.ts",
  "webui-test/tests/workflow-helpers.ts",
]);
const requiredArtifacts = Object.freeze([
  "browser-action-log.json",
  "playwright-result.json",
  "task-26-renew-busy.png",
  "task-26-skip-link-active.png",
  "task-26-skip-link-focused.png",
  "task-26-two-candidates-768.png",
  "task-26-two-candidates-mixed-readiness.png",
  "task-26-webui-active.png",
  "task-26-webui-focus.png",
  "task-26-webui-hover.png",
]);

if (process.argv[2] === undefined) throw new Error("evidence directory is required");
if (realpathSync(repository) !== repository || realpathSync(evidence) !== evidence) {
  throw new Error("repository and evidence paths must be canonical");
}

const digest = (contents) => createHash("sha256").update(contents).digest("hex");
const record = (root, path) => {
  const absolute = resolve(root, path);
  const entry = lstatSync(absolute);
  if (!entry.isFile() || entry.isSymbolicLink()) throw new Error(`${path} is not a regular file`);
  const contents = readFileSync(absolute);
  return {
    bytes: contents.length,
    mtimeNs: statSync(absolute, { bigint: true }).mtimeNs.toString(),
    path,
    sha256: digest(contents),
  };
};
const command = (program, commandArguments) =>
  execFileSync(program, commandArguments, { encoding: "utf8" }).trim();

const sources = sourcePaths.map((path) => record(repository, path));
const artifactNames = readdirSync(evidence)
  .filter((name) => name.endsWith(".png") || requiredArtifacts.includes(name))
  .sort();
for (const requiredArtifact of requiredArtifacts) {
  if (!artifactNames.includes(requiredArtifact)) {
    throw new Error(`required evidence artifact is missing: ${requiredArtifact}`);
  }
}
const artifacts = artifactNames.map((path) => record(evidence, path));
if (artifacts.length === 0) throw new Error("no evidence artifacts were found");
const newestSourceNs = sources.reduce(
  (maximum, source) => (BigInt(source.mtimeNs) > maximum ? BigInt(source.mtimeNs) : maximum),
  0n,
);
if (artifacts.some((artifact) => BigInt(artifact.mtimeNs) <= newestSourceNs)) {
  throw new Error("evidence predates current source");
}
const sourceSetSha256 = digest(
  Buffer.from(sources.map(({ path, sha256 }) => `${path}\0${sha256}\n`).join("")),
);
const playwrightReport = JSON.parse(readFileSync(resolve(evidence, "playwright-result.json"), "utf8"));
const playwrightStats = playwrightReport?.stats;
if (typeof playwrightStats !== "object" || playwrightStats === null ||
    !Number.isInteger(playwrightStats.expected) || playwrightStats.expected < 1 ||
    !Number.isInteger(playwrightStats.unexpected) || playwrightStats.unexpected !== 0 ||
    !Number.isInteger(playwrightStats.flaky) || playwrightStats.flaky !== 0) {
  throw new Error("Playwright evidence outcome is not a clean pass");
}
const firefoxReport = JSON.parse(readFileSync(resolve(evidence, "browser-action-log.json"), "utf8"));
if (firefoxReport?.outcome?.browser !== "firefox" || firefoxReport.outcome.status !== "passed") {
  throw new Error("Firefox evidence outcome is not a clean pass");
}
const receipt = {
  artifacts,
  browsers: {
    chromium: command(chromium.executablePath(), ["--version"]),
    firefox: command("firefox", ["--version"]),
    playwright: command("npx", ["playwright", "--version"]),
  },
  commands: [
    "PLAYWRIGHT_JSON_OUTPUT_FILE=<evidence>/playwright-result.json RKA_WEBUI_EVIDENCE_DIR=<evidence> npx playwright test --reporter=line,json",
    "node tests/webui_browser_harness.mjs <temporary-evidence>",
  ],
  generatedAt: new Date().toISOString(),
  gitHead: command("git", ["-C", repository, "rev-parse", "HEAD"]),
  node: process.version,
  outcomes: {
    firefox: firefoxReport.outcome,
    playwright: {
      expected: playwrightStats.expected,
      flaky: playwrightStats.flaky,
      status: "passed",
      unexpected: playwrightStats.unexpected,
    },
  },
  receiptWriterSha256: digest(readFileSync(new URL(import.meta.url))),
  schema: 2,
  sourceSetSha256,
  sources,
};
writeFileSync(
  resolve(evidence, "evidence-receipt.json"),
  `${JSON.stringify(receipt, null, 2)}\n`,
  { encoding: "utf8", mode: 0o600 },
);
