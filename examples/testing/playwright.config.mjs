// examples/testing/playwright.config.mjs
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  testMatch: /\.spec\.mjs$/,
  timeout: 30_000,
  reporter: [['list']],
  use: {
    browserName: 'chromium',
    headless: true,
    // zeroauthy's certificate comes from a CA generated at startup. Browsers
    // do not read NODE_EXTRA_CA_CERTS, so skip certificate checks for this
    // disposable server. (Alternatively add the CA to the browser's trust
    // store, e.g. an NSS database for Chromium on Linux.)
    ignoreHTTPSErrors: true,
    trace: 'retain-on-failure',
  },
});
