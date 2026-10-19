// tests/e2e/m15-console.spec.mjs: database connections in the admin console
// (Plan 15). A third operator (setup link E2E_ADMIN_SETUP_URL_M15, created by
// run-browser.sh) signs in, creates a connection, enables an application on
// it, sets a password policy (history 2, a custom dictionary word, personal
// data), and signs a user up through the hosted pages: a dictionary word is
// refused with its rule named, a good password is accepted. Then a custom
// database `login` script is tried, and the configuration value it prints and
// returns is masked. Deleting the connection deletes its user.
import { test, expect } from '@playwright/test';

const ADMIN = 'https://system.localhost:8443/admin/';
const EMAIL = 'operator-m15@e2e.local';
const PASSWORD = 'Operator-Password-2026';
const NAME = 'console-db';
const SECRET = 's3cr3t-token-7f3a9c';
const USER = 'console-user@e2e.local';
const GOOD = 'Quartz-Lantern-42';
const AUTHORIZE =
  'https://localhost:8443/authorize?' +
  new URLSearchParams({
    response_type: 'code', client_id: 'e2e-m15', redirect_uri: 'https://localhost:3443/m15-callback', scope: 'openid', state: 'm15',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  });

const LOGIN_SCRIPT = `async function login(email, password, callback) {
  console.log("calling the store with " + configuration.API_KEY);
  callback(null, { user_id: "stub-1", email: email, name: configuration.API_KEY });
}`;

test('an operator manages a database connection and its users', async ({ page }) => {
  const setup = process.env.E2E_ADMIN_SETUP_URL_M15;
  test.skip(!setup, 'E2E_ADMIN_SETUP_URL_M15 is set by run-browser.sh');

  const cspViolations = [];
  page.on('console', (m) => {
    if (/Content Security Policy|Refused to (load|execute|apply)/i.test(m.text())) cspViolations.push(m.text());
  });
  const nav = page.getByRole('navigation', { name: 'Sections' });
  const saved = page.getByRole('status').filter({ hasText: 'Saved' });

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

  // 2. Create a database connection.
  await nav.getByRole('link', { name: 'Database' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/connections$/);
  await expect(page.getByRole('link', { name: 'Username-Password-Authentication' })).toBeVisible();
  await page.getByRole('link', { name: 'Create connection' }).click();
  await page.fill('#conn-name', NAME);
  await page.getByRole('button', { name: 'Create connection' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/connections\/con_[A-Za-z0-9]{16}$/);
  await expect(page.getByRole('heading', { level: 1 })).toHaveText(NAME);
  const connURL = page.url();

  // 3. Enable an application on it.
  await page.getByRole('tab', { name: 'Applications' }).click();
  const app = page.getByTestId('app-e2e-m15');
  await expect(app).toBeVisible();
  const toggle = app.getByRole('switch', { name: 'Enable this connection for E2E Connections' });
  await expect(toggle).not.toBeChecked();
  await toggle.check();
  await expect(toggle).toBeChecked();
  await page.reload();
  await page.getByRole('tab', { name: 'Applications' }).click();
  await expect(page.getByTestId('app-e2e-m15').getByRole('switch')).toBeChecked();

  // 4. The password policy: history 2, a custom dictionary word, no personal
  //    data. The live checker agrees with the word before it is saved.
  await page.getByRole('tab', { name: 'Password policy' }).click();
  await page.fill('#pw-min', '10');
  await page.getByRole('checkbox', { name: /Refuse recently used passwords/ }).check();
  await page.fill('#pw-history-size', '2');
  await page.locator('#pw-dict-active').check();
  await page.fill('#pw-dict-custom', 'zebracrossing');
  await page.locator('#pw-profile-active').check();
  await page.fill('#pw-sample', 'ZebraCrossing');
  await expect(page.getByTestId('rule-dictionary')).toHaveAttribute('data-state', 'fail');
  await page.fill('#pw-sample', GOOD);
  await expect(page.getByTestId('rule-dictionary')).toHaveAttribute('data-state', 'pass');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(saved).toBeVisible();
  await page.reload();
  await page.getByRole('tab', { name: 'Password policy' }).click();
  await expect(page.locator('#pw-min')).toHaveValue('10');
  await expect(page.locator('#pw-history-size')).toHaveValue('2');
  await expect(page.locator('#pw-dict-custom')).toHaveValue('zebracrossing');

  // 5. Sign up through the hosted pages: a dictionary word is refused with
  //    its rule named, a good password is accepted.
  await page.goto(AUTHORIZE);
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.getByRole('link', { name: 'Create an account' }).click();
  await page.waitForURL(/localhost:8443\/u\/signup/);
  await page.fill('#email', USER);
  await page.fill('#password', 'ZebraCrossing');
  await page.click('button[type=submit]');
  await expect(page.getByRole('alert')).toHaveText('Password is too common.');
  await page.fill('#password', GOOD);
  await page.click('button[type=submit]');
  await page.waitForURL(/localhost:3443\/m15-callback\?code=/);

  // 6. A custom database login script, tried with a stub. The configuration
  //    value it prints and returns is masked in what Try shows.
  await page.goto(connURL);
  await page.getByRole('tab', { name: 'Custom database' }).click();
  await page.getByRole('checkbox', { name: /Use my own database/ }).check();
  await page.getByTestId('script-login').locator('summary').click();
  await page.fill('#script-src-login', LOGIN_SCRIPT);
  await page.getByRole('button', { name: 'Add a value' }).click();
  await page.getByTestId('config-new-0').getByLabel('Key').fill('API_KEY');
  await page.getByTestId('config-new-0').getByLabel('Value').fill(SECRET);
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(saved).toBeVisible();
  await expect(page.getByTestId('config-API_KEY')).toBeVisible();
  await expect(page.locator('body')).not.toContainText(SECRET);
  await page.getByTestId('try-login').getByRole('button', { name: 'Try', exact: true }).click();
  const result = page.getByTestId('try-result');
  await expect(result).toBeVisible();
  await expect(result).toContainText('stub-1');
  await expect(result).toContainText('■■■■■■■■');
  await expect(result).not.toContainText(SECRET);
  await expect(page.locator('body')).not.toContainText(SECRET);

  // 7. Delete the connection by typing its name. Its user goes with it: a
  //    new connection of the same name has no such user.
  await page.getByRole('tab', { name: 'Danger zone' }).click();
  await page.getByRole('button', { name: 'Delete connection' }).first().click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByRole('button', { name: 'Delete connection' })).toBeDisabled();
  await dialog.locator('#delete-confirm').fill(NAME);
  await dialog.getByRole('button', { name: 'Delete connection' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/connections$/);
  await expect(page.getByRole('link', { name: NAME, exact: true })).toHaveCount(0);

  await page.getByRole('link', { name: 'Create connection' }).click();
  await page.fill('#conn-name', NAME);
  await page.getByLabel('E2E Connections').check();
  await page.getByRole('button', { name: 'Create connection' }).click();
  await page.waitForURL(/\/admin\/t\/e2e\/connections\/con_[A-Za-z0-9]{16}$/);
  expect(page.url()).not.toBe(connURL);

  await page.goto(AUTHORIZE);
  await page.waitForURL(/localhost:8443\/u\/login/);
  await page.fill('#username', USER);
  await page.fill('#password', GOOD);
  await page.click('button[type=submit]');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page).toHaveURL(/localhost:8443\/u\/login/);

  expect(cspViolations).toEqual([]);
});
