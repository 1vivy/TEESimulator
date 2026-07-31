import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

const EXPECTED = Object.freeze({
  "chromium-1234/chrome-linux64/chrome": "0b20b130e7edd9dd51873be867761295fe0cfad490c2b9a64f95bd3cfc08fa71",
  "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell": "e11fc9ce65c96313476f7ee9844b6fb6a9220fb048693cfe9eee00acf4170a9f",
  "ffmpeg-1011/ffmpeg-linux": "460d44f3416005662f528d4b92e7b94ace924e8a0288106d3803b73c56eaadc8",
});
const expectedVersion = "Google Chrome for Testing 151.0.7922.34";
function fail(message) { throw new Error(message); }
const supplied = process.env.PLAYWRIGHT_BROWSERS_PATH ?? "";
if (!isAbsolute(supplied)) fail("browser root must be absolute");
const root = realpathSync(supplied);
if (root !== supplied) fail("browser root must be canonical");
const rootStat = statSync(root);
if (!rootStat.isDirectory() || (rootStat.mode & 0o777) !== 0o700) fail("browser root mode");
if (rootStat.uid !== process.getuid()) fail("browser root owner");
if (process.platform !== "linux" || process.arch !== "x64") fail("architecture");
const packageVersion = JSON.parse(readFileSync(new URL("../node_modules/@playwright/test/package.json", import.meta.url))).version;
if (packageVersion !== "1.62.0") fail("Playwright version drift");
const metadata = JSON.parse(readFileSync(new URL("../node_modules/playwright-core/browsers.json", import.meta.url)));
const chromium = metadata.browsers.find((entry) => entry.name === "chromium");
if (chromium?.revision !== "1234" || chromium.browserVersion !== "151.0.7922.34") fail("browser metadata drift");
for (const [name, digest] of Object.entries(EXPECTED)) {
  const candidate = join(root, name);
  const canonical = realpathSync(candidate);
  const fromRoot = relative(root, canonical);
  if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) fail("payload escaped browser root");
  let current = root;
  for (const part of name.split("/")) {
    current = join(current, part);
    const entry = lstatSync(current);
    if (entry.isSymbolicLink() || entry.uid !== process.getuid()) fail("payload ownership or symlink");
  }
  const actual = createHash("sha256").update(readFileSync(canonical)).digest("hex");
  if (actual !== digest) fail(`digest drift: ${name}`);
}
for (const name of Object.keys(EXPECTED).slice(0, 2)) {
  const reported = execFileSync(join(root, name), ["--version"], { encoding: "utf8" }).trim();
  if (reported !== expectedVersion) fail("executable version drift");
}
process.stdout.write('{"verified":true,"payloads":3,"executables":2}\n');
