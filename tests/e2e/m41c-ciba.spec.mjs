// Plan 41c: a backend asks a user to approve a sign-in by email; the user
// opens the link, signs in and approves (or denies), and the backend's poll
// receives the tokens (or access_denied).
import {test, expect} from '@playwright/test';
import {origin, secrets, start, poll, approvalLink, userID} from './m41c-ciba.mjs';

test.skip(!process.env.E2E_M41C_WORK, 'Run make e2e-ciba');
test.use({trace: 'off'});

async function browser(b) {
  return b.newContext({proxy: {server: 'http://127.0.0.1:9198'}, ignoreHTTPSErrors: true});
}

async function waitInterval() { await new Promise(r => setTimeout(r, 5200)); }

test('a user approves a backchannel request by email', async ({browser: b}) => {
  const alice = await userID('alice@ciba.e2e.local');
  const req = await start(alice, 'APPROVE-1');
  expect(req.status).toBe(200);
  const link = await approvalLink('APPROVE-1');
  const ctx = await browser(b);
  try {
    const page = await ctx.newPage();
    await page.goto(link);
    await expect(page.locator('#binding')).toHaveValue('APPROVE-1');
    await expect(page.getByText('Agent backend')).toBeVisible();
    await page.locator('button[name=action][value=approve]').click();
    await page.waitForURL(u => u.pathname === '/u/login');
    await page.fill('#username', 'alice@ciba.e2e.local');
    await page.fill('#password', secrets().password);
    await page.locator('button[type=submit]').first().click();
    await page.waitForURL(u => u.pathname === '/bc-verify/approved');
    await expect(page.getByText('Request approved')).toBeVisible();
    // The link is spent.
    await page.goto(link);
    await expect(page.getByText('expired')).toBeVisible();
  } finally {
    await ctx.close();
  }
  const tokens = await poll(req.body.auth_req_id);
  expect(tokens.status, JSON.stringify(tokens.body)).toBe(200);
  expect(tokens.body.id_token).toBeTruthy();
  expect(tokens.body.refresh_token).toBeTruthy();
  const claims = JSON.parse(Buffer.from(tokens.body.id_token.split('.')[1], 'base64url').toString());
  expect(claims.sub).toBe(alice);
  expect(claims.aud).toBe('agent');
  await waitInterval();
  expect((await poll(req.body.auth_req_id)).body.error).toBe('invalid_grant');
});

test('a user denies a backchannel request', async ({browser: b}) => {
  const req = await start(await userID('alice@ciba.e2e.local'), 'DENY-1');
  const link = await approvalLink('DENY-1');
  const ctx = await browser(b);
  try {
    const page = await ctx.newPage();
    await page.goto(link);
    await page.locator('button[name=action][value=deny]').click();
    await page.waitForURL(u => u.pathname === '/bc-verify/denied');
    await expect(page.getByText('Request denied')).toBeVisible();
  } finally {
    await ctx.close();
  }
  expect((await poll(req.body.auth_req_id)).body.error).toBe('access_denied');
});
