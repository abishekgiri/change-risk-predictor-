const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./e2e",
  timeout: 30000,
  retries: 1,
  use: {
    baseURL: process.env.DASHBOARD_UI_BASE_URL || "http://localhost:3000",
    trace: "on-first-retry",
  },
});
