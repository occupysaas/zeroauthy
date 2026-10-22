// tests/e2e/m17-console.spec.mjs: users in the admin console (Plan 17). A
// fourth operator (setup link E2E_ADMIN_SETUP_URL_M17, created by
// run-browser.sh) signs in, creates a user, finds them by a search query,
// edits app_metadata, blocks them (their password sign-in fails), unblocks
// them, revokes their sessions, creates a password-change link that is
// opened in a fresh browser context to set a new password (the user signs in
// with it), and sends a verification ticket that is opened the same way
// (the user shows as verified). The verification email written for a user
// created with "Send a verification email" is read from E2E_MAIL_DIR like
// m7-reset does.
import { test, expect } from '@playwright/test';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const ADMIN = 'https://system.localhost:8443/admin/';
const EMAIL = 'operator-m17@e2e.local';
const PASSWORD = 'Operator-Password-2026';
const USER = `console-m17-${Date.now()}@e2e.local`;
const FIRST = 'Quartz-Lantern-42';
const SECOND = 'Amber-Meadow-77';
const AUTHORIZE =
  'https://localhost:8443/authorize?' +
  new URLSearchParams({
    response_type: 'code', client_id: 'e2e-m17', redirect_uri: 'https://localhost:3443/m17-callback', scope: 'openid', state: 'm17',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  });

const decodeQP = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

// mailTo waits for an email to the address written after since that carries
// a link matching pattern, and returns the link.
async function mailLink(to, pattern, since) {
  const dir = process.env.E2E_MAIL_DIR;
  for (let i = 0; i < 50; i++) {
    const fresh = [];
    for (const f of (await readdir(dir)).filter((x) => x.endsWith('.eml'))) {
      const s = await stat(path.join(dir, f));
      if (s.mtimeMs >= since) fresh.push([s.mtimeMs, f]);
    }
    fresh.sort((a, b) => b[0] - a[0]);
    for (const [, f] of fresh) {
      const mail = decodeQP(await readFile(path.join(dir, f), 'utf8'));
      if (!mail.includes(to)) continue;
      const m = mail.match(pattern);
      if (m) return m[0];
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no email to ${to} with ${pattern}`);
}

// signIn tries the hosted login as the user. A sign-in that succeeds sends the
// browser to the application's callback (which this harness does not serve),
// so callback() resolves from the request, not from the page's URL.
async function signIn(page, password) {
  await page.goto(AUTHORIZE);
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', USER);
  await page.fill('#password', password);
  await page.click('button[type=submit]');
}
const calledBack = (page) => page.waitForRequest(/localhost:3443\/m17-callback\?code=/);

test('an operator manages a user in the console', async ({ page, browser }) => {
  const setup = process.env.E2E_ADMIN_SETUP_URL_M17;
  test.skip(!setup, 'E2E_ADMIN_SETUP_URL_M17 is set by run-browser.sh');

  const cspViolations = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to (load|execute|apply)/i.test(m.text())) cspViolations.push(m.text());
  });
  const nav = page.getByRole('navigation', { name: 'Sections' });
  const saved = page.getByRole('status').filter({ hasText: 'Saved' });
  const dialog = page.getByRole('dialog');

  // 1. Set a password and sign in.
  await page.goto(setup);
  await page.fill('#password', PASSWORD);
  await page.fill('#password_confirm', PASSWORD);
  await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');
  await page.goto(ADMIN);
  await page.waitForURL(/\/u\/login/);
  await page.fill('#username', EMAIL);
  await page.fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForURL(/\/admin\/t\/e2e\/$/);

  // 2. Create a user, with a verification email.
  await nav.getByRole('link', { name: 'Users' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/users$/);
  await page.getByRole('link', { name: 'Create user' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/users\/new$/);
  await page.selectOption('#user-connection', 'Username-Password-Authentication');
  await page.fill('#user-email', USER);
  await page.fill('#user-password', FIRST);
  const since = Date.now() - 1000;
  await page.getByRole('button', { name: 'Create user' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/users\/auth0(%7C|\|)[0-9a-f]{24}$/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText(USER);
  const userURL = page.url();
  await expect(page.getByText('(not verified)')).toBeVisible();
  // The verification email was written; its link is a single-use page.
  const emailed = await mailLink(USER, /https:\/\/localhost:8443\/u\/email-verification\?ticket=[A-Za-z0-9_-]+/, since);
  expect(emailed).toContain('/u/email-verification?ticket=');

  // 3. Find the user by a search query.
  await page.getByRole('link', { name: 'All users' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/users$/);
  await page.fill('#users-search', `email:"${USER}"`);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByRole('link', { name: USER })).toBeVisible();
  await expect(page.getByText(/^1–1 of 1$/)).toBeVisible();
  // A query the server refuses shows its message, not a failure page.
  await page.fill('#users-search', 'email:("x');
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.locator('#users-search-error')).toBeVisible();
  await page.fill('#users-search', `email:"${USER}"`);
  await page.getByRole('button', { name: 'Search' }).click();
  await page.getByRole('link', { name: USER }).click();
  await page.waitForURL(userURL);

  // 4. Edit app_metadata, and find the user by it.
  await page.getByRole('tab', { name: 'Metadata' }).click();
  await page.locator('#user-metadata-app').fill('{"plan": "pro", "seats": 4}');
  await page.getByRole('button', { name: 'Review changes' }).nth(1).click();
  await expect(page.getByTestId('diff-app')).toContainText('plan');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(saved).toBeVisible();
  await page.getByRole('tab', { name: 'Raw JSON' }).click();
  await expect(page.locator('body')).toContainText('"plan": "pro"');
  await expect(page.locator('body')).not.toContainText('password_hash');
  await page.getByRole('link', { name: 'All users' }).click();
  await page.fill('#users-search', `app_metadata.plan:pro AND email:"${USER}"`);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByRole('link', { name: USER })).toBeVisible();
  await page.fill('#users-search', `app_metadata.plan:free AND email:"${USER}"`);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByText('No user matches this search.')).toBeVisible();
  await page.goto(userURL);

  // 5. Block: the password sign-in fails. Unblock: it works.
  await page.getByRole('button', { name: 'Block', exact: true }).click();
  await dialog.getByRole('button', { name: 'Block user' }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Blocked');
  const blockedCtx = await browser.newContext();
  const blockedPage = await blockedCtx.newPage();
  await signIn(blockedPage, FIRST);
  await expect(blockedPage.getByRole('alert')).toBeVisible();
  await expect(blockedPage).toHaveURL(/localhost:8443\/u\/login/);
  await blockedCtx.close();
  await page.getByRole('button', { name: 'Unblock' }).click();
  await expect(page.getByText('The user can sign in again.')).toBeVisible();

  // 6. Signed in, the user has a session; the operator revokes it.
  const userCtx = await browser.newContext();
  const userPage = await userCtx.newPage();
  const userCalledBack = calledBack(userPage);
  await signIn(userPage, FIRST);
  await userCalledBack;
  await page.reload();
  await page.getByRole('tab', { name: 'Sessions and devices' }).click();
  await expect(page.getByRole('button', { name: 'Revoke all sessions' })).toBeVisible();
  await expect(page.getByText('No active sessions.')).toHaveCount(0);
  await page.getByRole('button', { name: 'Revoke all sessions' }).click();
  await dialog.getByRole('button', { name: 'Revoke all', exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await page.reload();
  await page.getByRole('tab', { name: 'Sessions and devices' }).click();
  await expect(page.getByText('No active sessions.')).toBeVisible();
  // The revoked session no longer signs the user in without a password.
  await userPage.goto(AUTHORIZE);
  await userPage.waitForURL(/localhost:8443\/u\/login/);
  await userCtx.close();

  // 7. A password-change link, opened in a fresh context.
  await page.getByRole('button', { name: 'Create password link' }).click();
  const resetLink = (await dialog.getByTestId('ticket-url').textContent()).trim();
  expect(resetLink).toContain('/u/reset-verify?ticket=');
  await dialog.getByRole('button', { name: 'Done' }).click();
  await expect(dialog).toHaveCount(0);
  const resetCtx = await browser.newContext();
  const resetPage = await resetCtx.newPage();
  await resetPage.goto(resetLink);
  await resetPage.fill('#password', SECOND);
  await resetPage.fill('#password_confirm', SECOND);
  await resetPage.click('button[type=submit]');
  await expect(resetPage.locator('h1')).toHaveText('Password changed');
  const resetCalledBack = calledBack(resetPage);
  await signIn(resetPage, SECOND);
  await resetCalledBack;
  await resetCtx.close();
  const staleCtx = await browser.newContext();
  const stalePage = await staleCtx.newPage();
  await signIn(stalePage, FIRST);
  await expect(stalePage.getByRole('alert')).toBeVisible();
  await staleCtx.close();

  // 8. A verification ticket, opened in a fresh context: Email Verified.
  await page.getByRole('button', { name: 'Create verification link' }).click();
  const verifyLink = (await dialog.getByTestId('ticket-url').textContent()).trim();
  expect(verifyLink).toContain('/u/email-verification?ticket=');
  await dialog.getByRole('button', { name: 'Done' }).click();
  const verifyCtx = await browser.newContext();
  const verifyPage = await verifyCtx.newPage();
  await verifyPage.goto(verifyLink);
  await expect(verifyPage.locator('body')).toContainText('Email Verified');
  await verifyCtx.close();
  await page.reload();
  await page.getByRole('tab', { name: 'Details' }).click();
  await expect(page.getByText('(verified)')).toBeVisible();

  // 9. Delete: type the email.
  await page.getByRole('button', { name: 'Delete user' }).click();
  await dialog.locator('#delete-confirm').fill(USER);
  await dialog.getByRole('button', { name: 'Delete user' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/users$/);
  await page.fill('#users-search', `email:"${USER}"`);
  await page.getByRole('button', { name: 'Search' }).click();
  await expect(page.getByText('No user matches this search.')).toBeVisible();

  expect(cspViolations).toEqual([]);
});
