// tests/e2e/playwright.config.mjs
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /m\d+-.*\.spec\.mjs/,
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true, ignoreHTTPSErrors: true, trace: 'retain-on-failure',
    // E2E_CHROMIUM: a Chromium already on the host, when Playwright's own
    // download is not available (offline containers).
    launchOptions: process.env.E2E_CHROMIUM ? { executablePath: process.env.E2E_CHROMIUM } : {} },
});
