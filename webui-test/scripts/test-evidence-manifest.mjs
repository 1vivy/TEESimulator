import { createHash } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repository = resolve(process.argv[2] ?? ".");
const verifier = join(repository, "webui-test/scripts/write-evidence-manifest.mjs");
const root = mkdtempSync(join(tmpdir(), "rka-evidence-manifest-test-"));
const clone = join(root, "repository");
const baseline = join(root, "baseline");
const captures = [
  "task-26-webui-375.png",
  "task-26-webui-768.png",
  "task-26-webui-1280.png",
  "task-26-webui-hover.png",
  "task-26-webui-focus.png",
  "task-26-webui-active.png",
  "task-26-failure-state.png",
  "task-26-confirm-awaiting.png",
  "task-26-confirm-mismatch.png",
  "task-26-confirm-busy.png",
  "task-26-confirm-accepted.png",
  "task-26-confirm-refused.png",
];
const browserReceipt = {
  browserVersion: "151.0.7922.34",
  executables: [
    {
      path: "chromium-1234/chrome-linux64/chrome",
      version: "Google Chrome for Testing 151.0.7922.34",
    },
    {
      path: "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell",
      version: "Google Chrome for Testing 151.0.7922.34",
    },
  ],
  packageVersion: "1.62.0",
  payloads: [
    {
      path: "chromium-1234/chrome-linux64/chrome",
      sha256: "0b20b130e7edd9dd51873be867761295fe0cfad490c2b9a64f95bd3cfc08fa71",
    },
    {
      path: "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell",
      sha256: "e11fc9ce65c96313476f7ee9844b6fb6a9220fb048693cfe9eee00acf4170a9f",
    },
    {
      path: "ffmpeg-1011/ffmpeg-linux",
      sha256: "460d44f3416005662f528d4b92e7b94ace924e8a0288106d3803b73c56eaadc8",
    },
  ],
  revision: "1234",
  verified: true,
};

function writeJson(path, value) {
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function runFinal(evidence) {
  return spawnSync(
    process.execPath,
    [
      verifier,
      "final",
      clone,
      evidence,
      join(evidence, "visual-review-a.txt"),
      join(evidence, "visual-review-b.txt"),
    ],
    { encoding: "utf8" },
  );
}

function mutateReceipt(evidence, mutation) {
  const path = join(evidence, "capture-receipt.json");
  const receipt = JSON.parse(readFileSync(path, "utf8"));
  mutation(receipt);
  writeJson(path, receipt);
}

function mutation(name, change, { keepManifest = false } = {}) {
  const evidence = join(root, name);
  cpSync(baseline, evidence, { preserveTimestamps: true, recursive: true });
  if (!keepManifest) rmSync(join(evidence, "evidence-manifest.json"));
  change(evidence);
  const result = runFinal(evidence);
  const rejected = result.status !== 0;
  process.stdout.write(`${name}: ${rejected ? "REJECTED" : "ACCEPTED"}\n`);
  return rejected;
}

  try {
  execFileSync("git", ["clone", "--quiet", "--no-hardlinks", repository, clone]);
  const fixtureTestPath = "webui-test/scripts/test-evidence-manifest.mjs";
  cpSync(join(repository, fixtureTestPath), join(clone, fixtureTestPath));
  execFileSync("git", ["-C", clone, "config", "user.name", "Evidence Test"]);
  execFileSync("git", ["-C", clone, "config", "user.email", "evidence@example.invalid"]);
  execFileSync("git", ["-C", clone, "config", "commit.gpgsign", "false"]);
  execFileSync("git", ["-C", clone, "add", fixtureTestPath]);
  const stagedFixture = spawnSync("git", ["-C", clone, "diff", "--cached", "--quiet"]);
  if (stagedFixture.status === 1) execFileSync("git", ["-C", clone, "commit", "--quiet", "-m", "add evidence test fixture"]);
  else if (stagedFixture.status !== 0) throw new Error("could not inspect staged evidence fixture");
  mkdirSync(baseline);
  const png = Buffer.alloc(24);
  Buffer.from("89504e470d0a1a0a", "hex").copy(png);
  png.write("IHDR", 12, "ascii");
  png.writeUInt32BE(1280, 16);
  png.writeUInt32BE(900, 20);
  const future = new Date(Date.now() + 5_000);
  for (const filename of captures) {
    const path = join(baseline, filename);
    writeFileSync(path, png);
    utimesSync(path, future, future);
  }
  writeFileSync(join(baseline, "browser-receipt.json"), `${JSON.stringify(browserReceipt)}\n`);
  execFileSync(process.execPath, [
    verifier,
    "capture",
    clone,
    baseline,
    join(baseline, "browser-receipt.json"),
  ]);
  const reviewTime = new Date(future.getTime() + 5_000);
  for (const reviewer of ["visual-review-a.txt", "visual-review-b.txt"]) {
    const path = join(baseline, reviewer);
    writeFileSync(path, `Independent ${reviewer}\nVERDICT: PASS\n`);
    utimesSync(path, reviewTime, reviewTime);
  }
  const baselineResult = runFinal(baseline);
  if (baselineResult.status !== 0) {
    throw new Error(`baseline rejected: ${baselineResult.stderr}`);
  }

  const results = [
    mutation("forged-source-hash", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.sources[0].sha256 = "0".repeat(64);
      }),
    ),
    mutation("forged-source-blob", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.sources[0].gitBlob = "0".repeat(40);
      }),
    ),
    mutation("forged-capture-hash", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.captures[0].sha256 = "0".repeat(64);
      }),
    ),
    mutation("forged-capture-dimensions", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.captures[0].width += 1;
      }),
    ),
    mutation("forged-capture-state", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.captures[0].stateId = "forged-state";
      }),
    ),
    mutation("forged-browser-hash", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.browserReceiptSha256 = "0".repeat(64);
      }),
    ),
    mutation("forged-browser-payload", (evidence) => {
      const path = join(evidence, "browser-receipt.json");
      const forged = structuredClone(browserReceipt);
      forged.packageVersion = "0.0.0";
      const bytes = Buffer.from(`${JSON.stringify(forged)}\n`);
      writeFileSync(path, bytes);
      mutateReceipt(evidence, (receipt) => {
        receipt.browserReceipt = forged;
        receipt.browserReceiptSha256 = createHash("sha256").update(bytes).digest("hex");
      });
    }),
    mutation(
      "forged-reviewer-hash",
      (evidence) => {
        const path = join(evidence, "evidence-manifest.json");
        const manifest = JSON.parse(readFileSync(path, "utf8"));
        manifest.reviewers[0].sha256 = "0".repeat(64);
        writeJson(path, manifest);
      },
      { keepManifest: true },
    ),
    mutation("reviewer-revise", (evidence) =>
      writeFileSync(join(evidence, "visual-review-a.txt"), "VERDICT: REVISE\n"),
    ),
    mutation("extra-capture", (evidence) => {
      cpSync(join(evidence, captures[0]), join(evidence, "extra.png"), {
        preserveTimestamps: true,
      });
      mutateReceipt(evidence, (receipt) => {
        receipt.captures.push({ ...receipt.captures[0], filename: "extra.png" });
      });
    }),
    mutation("missing-capture", (evidence) => {
      rmSync(join(evidence, captures.at(-1)));
      mutateReceipt(evidence, (receipt) => {
        receipt.captures.pop();
      });
    }),
    mutation("duplicate-source", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.sources.push({ ...receipt.sources[0] });
      }),
    ),
    mutation("path-escape", (evidence) =>
      mutateReceipt(evidence, (receipt) => {
        receipt.sources[0].path = "../outside";
      }),
    ),
    mutation("capture-symlink", (evidence) => {
      const path = join(evidence, captures[0]);
      rmSync(path);
      symlinkSync(captures[1], path);
      if (!lstatSync(path).isSymbolicLink()) throw new Error("symlink fixture failed");
    }),
    mutation("stale-capture", (evidence) => {
      const path = join(evidence, captures[0]);
      utimesSync(path, new Date(0), new Date(0));
      mutateReceipt(evidence, (receipt) => {
        receipt.captures[0].mtimeNs = statSync(path, { bigint: true }).mtimeNs.toString();
      });
    }),
    mutation("noncanonical-receipt", (evidence) => {
      const path = join(evidence, "capture-receipt.json");
      const receipt = JSON.parse(readFileSync(path, "utf8"));
      writeFileSync(path, JSON.stringify(receipt));
    }),
  ];
  if (results.some((rejected) => !rejected)) {
    throw new Error("one or more evidence mutations were accepted");
  }
  process.stdout.write(`EVIDENCE_MANIFEST_MUTATIONS_PASS count=${results.length}\n`);
} finally {
  if (process.env.RKA_KEEP_EVIDENCE_TEST_TMP === "1") {
    process.stdout.write(`fixture=${root}\n`);
  } else {
    rmSync(root, { force: true, recursive: true });
  }
}
