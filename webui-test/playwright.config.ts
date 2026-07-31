import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: { baseURL: "http://127.0.0.1:8765", screenshot: "only-on-failure" },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: "python3 ../tests/webui_server.py --root ../build/webui-root --port 8765 --nonce-file ../build/webui-nonce",
    cwd: import.meta.dirname,
    reuseExistingServer: false,
    url: "http://127.0.0.1:8765",
  },
});
