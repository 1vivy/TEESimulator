import { defineConfig } from "@playwright/test";

const port = process.env.RKA_WEBUI_TEST_PORT ?? "8765";
if (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65_535) {
  throw new Error("RKA_WEBUI_TEST_PORT must be a valid TCP port");
}
const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: { baseURL, screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: `python3 ../tests/webui_server.py --root /tmp/rw --port ${port} --nonce-file ../build/webui-nonce`,
    cwd: import.meta.dirname,
    reuseExistingServer: false,
    url: baseURL,
  },
});
