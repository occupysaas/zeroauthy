// tests/e2e/playwright.config.mjs
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /m\d+[a-z]?-.*\.spec\.mjs/,
  // Apple needs its own cross-site upstream and native-code fixture, GitHub
  // its own upstream fixture and tenants. Keep them out of general discovery;
  // run-m39a-apple.sh and run-m39c-github.sh enable their complete lanes.
  testIgnore: [
    ...(process.env.E2E_M41A === '1' ? [] : ['m41a-logout.spec.mjs']),
    ...(process.env.E2E_M37A === '1' ? [] : ['m37a-saml.spec.mjs']),
    ...(process.env.E2E_M39A === '1' ? [] : ['m39a-apple.spec.mjs']),
    ...(process.env.E2E_M39C === '1' ? [] : ['m39c-github.spec.mjs']),
  ],
  timeout: 60_000,
  workers: 1,
  reporter: [['list']],
  use: { browserName: 'chromium', headless: true, ignoreHTTPSErrors: true, trace: 'retain-on-failure',
    // E2E_CHROMIUM: a Chromium already on the host, when Playwright's own
    // download is not available (offline containers).
    launchOptions: process.env.E2E_CHROMIUM ? { executablePath: process.env.E2E_CHROMIUM } : {} },
});
