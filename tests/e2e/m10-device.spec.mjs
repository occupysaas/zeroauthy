// Black-box test (CLEAN_ROOM.md): auth0.net's Authentication API client
// (tests/e2e/dotnet-device, run with podman) starts the device flow and polls;
// Chromium plays the user at /activate. run-browser.sh builds the client and
// sets E2E_DOTNET_DIR; without it (E2E_IN_CONTAINER=1) the suite skips.
import { test, expect } from '@playwright/test';
import { spawn, execFile } from 'node:child_process';
import { createInterface } from 'node:readline';
import { randomBytes } from 'node:crypto';

const SDK_IMAGE = 'mcr.microsoft.com/dotnet/sdk:10.0.400-noble';
const containers = [];

// startDevice runs the client for audience and scope. It resolves the first
// stdout line (the "code" event) and returns, with it, a promise for the
// last line and the exit code.
async function startDevice(audience, scope) {
  const name = `za-e2e-device-${randomBytes(4).toString('hex')}`;
  containers.push(name);
  const child = spawn('podman', ['run', '--rm', '--name', name, '--network', 'host',
    '-v', `${process.env.E2E_DOTNET_DIR}:/app:ro`, '-v', `${process.env.E2E_CERT}:/certs/e2e.crt:ro`,
    SDK_IMAGE, 'sh', '-c',
    'cp /certs/e2e.crt /usr/local/share/ca-certificates/ && update-ca-certificates >/dev/null 2>&1 && dotnet /app/DeviceE2E.dll "$@"', '--',
    'https://localhost:8443/', 'e2e-device', audience, scope], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = [];
  let gotCode;
  const code = new Promise((resolve, reject) => { gotCode = resolve; child.on('error', reject); });
  createInterface({ input: child.stdout }).on('line', (l) => {
    lines.push(l);
    if (lines.length === 1) gotCode(JSON.parse(l));
  });
  const final = new Promise((resolve) => child.on('close', (exit) => {
    gotCode(null);
    resolve({ exit, last: lines.length > 1 ? JSON.parse(lines.at(-1)) : null });
  }));
  const first = await code;
  expect(first?.event).toBe('code');
  return { code: first, final };
}

test.describe.configure({ mode: 'serial', timeout: 180_000 });
test.skip(!process.env.E2E_DOTNET_DIR, 'needs the auth0.net client built by run-browser.sh (podman on the host)');

// One browser context for the file: the second test reuses the login
// session from the first (D10).
let context, page;
test.beforeAll(async ({ browser }) => {
  context = await browser.newContext({ ignoreHTTPSErrors: true });
  page = await context.newPage();
});
test.afterAll(async () => {
  await context?.close();
  for (const name of containers) await new Promise((r) => execFile('podman', ['rm', '-f', '-i', name], () => r()));
});

const TOKENS = { event: 'tokens', access: true, id: true, refresh: true, refreshed: true };

async function expectConfirmation(userCode) {
  await page.waitForURL(/localhost:8443\/device\/confirmation\?state=/);
  await expect(page.locator('#code')).toHaveValue(userCode);
  await expect(page.locator('strong.client')).toHaveText('E2E Device');
}

test('typed code: confirmation, login, no consent, tokens', async () => {
  const { code, final } = await startDevice('https://api.e2e.local', 'openid offline_access');
  expect(code.verification_uri).toBe('https://localhost:8443/activate');
  expect(code.verification_uri_complete).toBe(`https://localhost:8443/activate?user_code=${code.user_code}`);
  expect([code.interval, code.expires_in]).toEqual([5, 900]);

  await page.goto(code.verification_uri);
  await page.fill('#code', code.user_code);
  await page.click('button[type=submit]');
  await expectConfirmation(code.user_code);
  await page.click('button[value=confirm]');

  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', 'alice@e2e.local');
  await page.fill('#password', 'Correct-Horse-Battery-9');
  const seen = [];
  page.on('framenavigated', (f) => { if (f === page.mainFrame()) seen.push(f.url()); });
  await page.click('button[type=submit]');
  await page.waitForURL('https://localhost:8443/device/success');
  expect(seen.filter((u) => u.includes('/u/consent'))).toEqual([]); // first party, skip consent (D4)
  page.removeAllListeners('framenavigated');
  await expect(page.locator('[role=status]')).toHaveText('You can go back to your device now.');

  expect(await final).toEqual({ exit: 0, last: TOKENS });
});

test('complete URI: confirmation first, session reused, consent, tokens', async () => {
  const { code, final } = await startDevice('https://consent.e2e.local', 'openid offline_access read:things');
  const seen = [];
  page.on('framenavigated', (f) => { if (f === page.mainFrame()) seen.push(f.url()); });
  await page.goto(code.verification_uri_complete);
  await expectConfirmation(code.user_code); // the first screen (D1)
  await page.click('button[value=confirm]');
  await page.waitForURL(/localhost:8443\/u\/consent/);
  await expect(page.locator('ul.scopes')).toContainText(/read:things|Read things/);
  await page.click('button[value=accept]');
  await page.waitForURL('https://localhost:8443/device/success');
  expect(seen.filter((u) => u.includes('/u/login'))).toEqual([]); // session reused (D10)
  page.removeAllListeners('framenavigated');

  expect(await final).toEqual({ exit: 0, last: TOKENS });
});

test('cancel: denied page, access_denied on the device', async () => {
  const { code, final } = await startDevice('https://api.e2e.local', 'openid offline_access');
  await page.goto(code.verification_uri_complete);
  await expectConfirmation(code.user_code);
  await page.click('button[value=cancel]');
  await page.waitForURL('https://localhost:8443/device/denied');
  await expect(page.locator('[role=status]')).toContainText('was not given access');

  expect(await final).toEqual({ exit: 1, last: { event: 'error', error: 'access_denied' } });
});

test('wrong codes: five misses, then the transaction ends', async () => {
  await page.goto('https://localhost:8443/activate');
  for (let i = 0; i < 5; i++) {
    await page.fill('#code', 'BBBB-BBBB');
    const res = page.waitForResponse((r) => r.url() === 'https://localhost:8443/activate' && r.request().method() === 'POST');
    await page.click('button[type=submit]');
    expect((await res).status()).toBe(400);
    await expect(page.locator('[role=alert]')).toHaveText(
      'That code is not valid or has expired. Check the code on your device and try again.');
  }
  await page.fill('#code', 'BBBB-BBBB');
  await page.click('button[type=submit]');
  await expect(page.locator('main')).toContainText(
    'Your login session has expired or is invalid. Return to the application and start again.');
  await expect(page.locator('#code')).toHaveCount(0);
});
