// tests/e2e/m14-console.spec.mjs: APIs, machine-to-machine access and
// operators in the admin console (Plan 14). A second operator (setup link
// E2E_ADMIN_SETUP_URL_M14, created by run-browser.sh) signs in, creates an
// API with two permissions and a machine-to-machine application, authorizes
// it with one permission, runs the quick start's token request from the
// test, removes a permission, deletes the API, then invites an operator and
// removes them.
import { test, expect } from '@playwright/test';

const ADMIN = 'https://system.localhost:8443/admin/';
const EMAIL = 'operator-m14@e2e.local';
const PASSWORD = 'Operator-Password-2026';
const IDENTIFIER = 'https://console-api.e2e.test';

// shellWords splits a shell command the way sh would for the quick start's
// curl: single quotes, backslash-newline continuations, plain words.
function shellWords(cmd) {
  const words = [];
  let cur = null;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === "'") {
      const end = cmd.indexOf("'", i + 1);
      cur = (cur ?? '') + cmd.slice(i + 1, end);
      i = end;
    } else if (c === '\\' && cmd[i + 1] === '\n') {
      i++;
    } else if (/\s/.test(c)) {
      if (cur !== null) words.push(cur);
      cur = null;
    } else {
      cur = (cur ?? '') + c;
    }
  }
  if (cur !== null) words.push(cur);
  return words;
}

// runCurl performs the request of a copied `curl` command with fetch:
// --url, --request, --header, --data (name=value, sent as is),
// --data-urlencode (name=value, value encoded) and --user.
async function runCurl(cmd) {
  const w = shellWords(cmd);
  expect(w[0]).toBe('curl');
  let url;
  let method = 'GET';
  const headers = {};
  const fields = [];
  for (let i = 1; i < w.length; i++) {
    const flag = w[i];
    if (flag === '--url') url = w[++i];
    else if (flag === '--request') method = w[++i];
    else if (flag === '--header') {
      const h = w[++i];
      headers[h.slice(0, h.indexOf(':')).trim().toLowerCase()] = h.slice(h.indexOf(':') + 1).trim();
    } else if (flag === '--data') {
      const [k, ...v] = w[++i].split('=');
      fields.push([k, v.join('=')]);
    } else if (flag === '--data-urlencode') {
      const f = w[++i];
      const at = f.indexOf('=');
      fields.push([f.slice(0, at), f.slice(at + 1)]);
    } else if (flag === '--user') headers.authorization = 'Basic ' + Buffer.from(w[++i]).toString('base64');
    else throw new Error('unsupported curl option ' + flag);
  }
  const body = new URLSearchParams(fields).toString();
  return fetch(url, { method, headers, body: method === 'GET' ? undefined : body });
}

test('an operator manages APIs, machine-to-machine access and operators', async ({ page }) => {
  const setup = process.env.E2E_ADMIN_SETUP_URL_M14;
  test.skip(!setup, 'E2E_ADMIN_SETUP_URL_M14 is set by run-browser.sh');

  const cspViolations = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to (load|execute|apply)/i.test(m.text())) cspViolations.push(m.text());
  });
  const nav = page.getByRole('navigation', { name: 'Sections' });

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

  // 2. Create an API with two permissions.
  await nav.getByRole('link', { name: 'APIs' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/apis$/);
  await page.getByRole('link', { name: 'Create API' }).click();
  await page.fill('#api-name', 'Console API');
  await page.fill('#api-identifier', IDENTIFIER);
  await page.getByRole('button', { name: 'Create API' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/apis\/[0-9a-f]{24}$/);
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Console API');
  const apiURL = page.url();
  await page.getByRole('tab', { name: 'Permissions' }).click();
  for (const [value, description] of [['read:items', 'Read items'], ['write:items', 'Write items']]) {
    await page.fill('#scope-value', value);
    await page.fill('#scope-description', description);
    await page.getByRole('button', { name: 'Add permission' }).click();
  }
  await page.getByRole('button', { name: 'Save permissions' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved' })).toBeVisible();

  // 3. Create a machine-to-machine application.
  await nav.getByRole('link', { name: 'Applications' }).click();
  await page.getByRole('link', { name: 'Create application' }).click();
  await page.fill('#app-name', 'Console M2M');
  await page.getByRole('radio', { name: /Machine to machine/ }).check();
  await page.getByRole('button', { name: 'Create application' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/applications\/[A-Za-z0-9]{32}$/);
  const appURL = page.url();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Console M2M');

  // 4. Authorize it for the API with one permission.
  await page.getByRole('tab', { name: 'APIs', exact: true }).click();
  await page.selectOption('#grant-api', IDENTIFIER);
  await page.getByRole('button', { name: 'Authorize', exact: true }).click();
  const grant = page.getByTestId('grant-' + IDENTIFIER);
  await expect(grant).toBeVisible();
  await grant.getByRole('checkbox', { name: /read:items/ }).check();
  await grant.getByRole('button', { name: 'Save permissions' }).click();
  await expect(grant.getByRole('status').filter({ hasText: 'Saved' })).toBeVisible();

  // 5. The quick start's token request, copied and run from here.
  await page.getByRole('tab', { name: 'Quick start' }).click();
  await page.getByTestId('reveal').click();
  const snippet = page.locator('pre', { hasText: '/oauth/token' }).first();
  await expect(snippet).toContainText(/client_secret=[A-Za-z0-9]{64}/);
  const curl = await snippet.textContent();
  expect(curl).toContain(IDENTIFIER);
  const res = await runCurl(curl);
  expect(res.status).toBe(200);
  const token = await res.json();
  expect(token.scope).toBe('read:items');
  expect(JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url')).aud).toBe(IDENTIFIER);

  // 6. Remove a permission nobody holds, then one a grant carries (asks
  //    first), and look at the token again.
  await page.goto(apiURL);
  await page.getByRole('tab', { name: 'Permissions' }).click();
  await page.getByRole('button', { name: 'Remove write:items' }).click();
  await page.getByRole('button', { name: 'Save permissions' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Remove write:items' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Remove read:items' }).click();
  await page.getByRole('button', { name: 'Save permissions' }).click();
  const confirm = page.getByRole('dialog');
  await expect(confirm).toContainText('read:items');
  await confirm.getByRole('button').first().click();
  await expect(page.getByTestId('scopes-empty')).toBeVisible();
  const emptied = await runCurl(curl);
  expect(emptied.status).toBe(200);
  expect((await emptied.json()).scope ?? '').toBe('');

  // 7. Delete the API by typing its name; its grant goes with it.
  await page.getByRole('tab', { name: 'Danger zone' }).click();
  await page.getByRole('button', { name: 'Delete API' }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Delete API' })).toBeDisabled();
  await dialog.locator('#delete-confirm').fill('Console API');
  await dialog.getByRole('button', { name: 'Delete API' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/apis$/);
  await expect(page.getByRole('link', { name: 'Console API' })).toHaveCount(0);
  const gone = await runCurl(curl);
  expect(gone.status).toBe(403);
  await page.goto(appURL);
  await page.getByRole('tab', { name: 'APIs', exact: true }).click();
  await expect(page.getByTestId('grant-' + IDENTIFIER)).toHaveCount(0);

  // 8. Invite an operator on the system tenant, then remove them.
  await page.getByRole('button', { name: 'Switch tenant' }).click();
  await page.getByRole('menuitem', { name: /^system/ }).click();
  await nav.getByRole('link', { name: 'Operators' }).click();
  await page.waitForURL(/\/admin\/t\/system\/operators$/);
  await page.getByRole('button', { name: 'Invite operator' }).click();
  await page.fill('#invite-email', 'invited@e2e.local');
  await page.getByRole('button', { name: 'Create invitation' }).click();
  await expect(page.locator('#invite-url')).toHaveValue(/^https:\/\//);
  await page.getByRole('button', { name: 'Done' }).click();
  const row = page.getByTestId('operator-invited@e2e.local');
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Remove invited@e2e.local' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(page.getByTestId('status')).toContainText('invited@e2e.local was removed.');
  await expect(row).toHaveCount(0);

  expect(cspViolations).toEqual([]);
});
