// tests/e2e/playwright.config.mjs
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /m4-.*\.spec\.mjs/,
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true, ignoreHTTPSErrors: true, trace: 'retain-on-failure' },
});
