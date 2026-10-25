import { test, expect } from '@playwright/test';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

const ADMIN = 'https://system.localhost:8443/admin/';
const PASSWORD = 'Operator-Password-2026';
const decodeQP = (s) => s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));

async function mailFor(to, since) {
  const dir = process.env.E2E_MAIL_DIR;
  for (let i = 0; i < 100; i++) {
    const out = [];
    for (const file of (await readdir(dir)).filter(f => f.endsWith('.eml'))) {
      const full = path.join(dir, file);
      if ((await stat(full)).mtimeMs < since) continue;
      const body = decodeQP(await readFile(full, 'utf8'));
      if (body.includes(to)) out.push(body);
    }
    if (out.length) return out;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`directory mail for ${to} did not arrive`);
}

async function signup(origin, email) {
  const response = await fetch(`${origin}/dbconnections/signup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    client_id: 'e2e-spa', connection: 'Username-Password-Authentication', email, password: 'M21-Quartz-Lantern-42!',
  }) });
  const text = await response.text();
  assertStatus(response.status, text);
}
function assertStatus(status, body) { if (status !== 200) throw new Error(`signup returned ${status}: ${body}`); }

test('email delivery stays tenant-local and console edits keep safe uncertainty behavior', async ({ page, browser }) => {
  test.setTimeout(180_000);
  test.skip(!process.env.E2E_ADMIN_SETUP_URL_M21, 'Use make e2e-email for the isolated Plan 21 fixtures');
  await page.goto(process.env.E2E_ADMIN_SETUP_URL_M21);
  await page.fill('#password', PASSWORD); await page.fill('#password_confirm', PASSWORD); await page.click('button[type=submit]');
  await expect(page.locator('h1')).toHaveText('Password changed');
  await page.goto(ADMIN); await page.waitForURL(/\/u\/login/);
  await page.fill('#username', 'operator-m21@e2e.local'); await page.fill('#password', PASSWORD); await page.click('button[type=submit]');
  await page.waitForURL(/\/admin\/t\/e2e\/$/);

  await page.goto('https://system.localhost:8443/admin/t/e2e/emails');
  await page.getByRole('tab', { name: 'Templates' }).click();
  await page.selectOption('#email-template-select', 'verify_email');
  await expect(page.getByText('Saved and disabled', { exact: true })).toBeVisible();
  await page.locator('input[type=checkbox]').first().check();
  await page.fill('#email-template-subject', 'M21 Custom Verify');
  await page.fill('#email-template-body', '<p>Custom verification</p><a href="{{ url }}">Verify address</a>');
  await page.getByRole('button', { name: 'Save template', exact: true }).click();
  await expect(page.getByText('Changes saved.', { exact: true })).toBeVisible();

  const email = `m21-primary-${Date.now()}@e2e.local`;
  const since = Date.now() - 1000;
  await signup('https://localhost:8443', email);
  const initial = await mailFor(email, since);
  const verify = initial.flatMap(m => [...m.matchAll(/https:\/\/(?:localhost|system\.localhost):8443\/u\/email-verification\?ticket=[A-Za-z0-9_-]+/g)].map(x => x[0]))[0];
  expect(verify, `message subjects=${initial.map(m => m.match(/Subject:.*$/m)?.[0])}; hasVerificationPath=${initial.some(m => m.includes('/u/email-verification?ticket='))}`).toBeTruthy();
  expect(initial.some(m => m.includes('M21 Custom Verify'))).toBe(true);
  const userContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const userPage = await userContext.newPage();
  try {
    await userPage.goto(verify);
    await expect(userPage.locator('body')).toContainText('Email Verified');
    await expect.poll(async () => (await mailFor(email, since)).length).toBe(2);
    let messages = await mailFor(email, since);
    expect(messages.some(m => m.includes('M21 welcome') || m.includes('M21 Welcome'))).toBe(true);
    await userPage.goto(verify);
    await expect(userPage.locator('body')).toContainText('could not be verified');
    await page.waitForTimeout(300);
    expect((await mailFor(email, since)).length).toBe(2);
  } finally { await userContext.close(); }

  // A second tenant sends through its explicit allowlisted STARTTLS SMTP sink.
  const sink = process.env.E2E_EMAIL_SINK_URL;
  const priorSMTP = await fetch(`${sink}/messages`).then(r => r.json());
  const secondaryEmail = `m21-secondary-${Date.now()}@e2e.local`;
  const secondarySince = Date.now() - 1000;
  await signup('https://secondary.localhost:8443', secondaryEmail);
  await expect.poll(async () => (await fetch(`${sink}/messages`).then(r => r.json())).length).toBe(priorSMTP.length + 1);
  let smtpMessages = await fetch(`${sink}/messages`).then(r => r.json());
  const secondaryLink = smtpMessages.join('\n').match(/https:\/\/[^\s"<>]+\/u\/email-verification\?ticket=[A-Za-z0-9_-]+/)?.[0];
  expect(secondaryLink).toContain('secondary.localhost:8443');
  expect(secondaryLink).toBeTruthy();
  const secondaryContext = await browser.newContext({ ignoreHTTPSErrors: true });
  const secondaryPage = await secondaryContext.newPage();
  try {
    await secondaryPage.goto(secondaryLink);
    await expect(secondaryPage.locator('body')).toContainText('Email Verified');
    await expect.poll(async () => (await fetch(`${sink}/messages`).then(r => r.json())).length).toBe(priorSMTP.length + 2);
    smtpMessages = await fetch(`${sink}/messages`).then(r => r.json());
    const forSecondary = smtpMessages.slice(priorSMTP.length);
    expect(forSecondary.every(m => m.includes(secondaryEmail))).toBe(true);
    expect(forSecondary.some(m => m.includes('Secondary verify'))).toBe(true);
    expect(forSecondary.some(m => m.includes('Secondary welcome'))).toBe(true);
    expect((await mailFor(email, since)).length).toBe(2);
  } finally { await secondaryContext.close(); }

  // Hold an old tenant GET, switch tenant, and prove its late response cannot replace the current editor.
  await page.goto('https://system.localhost:8443/admin/t/e2e/emails'); await page.getByRole('tab', { name: 'Templates' }).click();
  let releaseOld; const held = new Promise(resolve => { releaseOld = resolve; });
  let signalOld; const oldStarted = new Promise(resolve => { signalOld = resolve; });
  await page.route('https://localhost:8443/api/v2/email-templates/verify_email', async route => {
    const response = await route.fetch(); signalOld(); await held; await route.fulfill({ response });
  });
  await page.selectOption('#email-template-select', 'verify_email_by_code');
  await page.selectOption('#email-template-select', 'verify_email');
  await oldStarted;
  await page.getByRole('button', { name: 'Switch tenant' }).click();
  await page.getByRole('menuitem').filter({ hasText: 'secondary' }).click();
  await page.goto('https://system.localhost:8443/admin/t/secondary/emails'); await page.getByRole('tab', { name: 'Templates' }).click();
  await expect(page.locator('#email-template-subject')).toHaveValue('Secondary verify');
  releaseOld();
  await expect(page.locator('#email-template-subject')).toHaveValue('Secondary verify');
  await page.unroute('https://localhost:8443/api/v2/email-templates/verify_email');

  // A forbidden write preserves edits; an aborted test-send is attempted once and is never retried.
  let writes = 0;
  await page.route('https://secondary.localhost:8443/api/v2/email-templates/verify_email', async route => {
    if (route.request().method() === 'PUT') { writes++; await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ errorCode: 'insufficient_scope', message: 'Forbidden' }) }); }
    else await route.continue();
  });
  await page.fill('#email-template-subject', 'Keep this forbidden draft');
  await page.getByRole('button', { name: 'Save template', exact: true }).click();
  await expect(page.locator('#email-template-subject')).toHaveValue('Keep this forbidden draft');
  expect(writes).toBe(1);
  await page.unroute('https://secondary.localhost:8443/api/v2/email-templates/verify_email');

  await page.getByRole('tab', { name: 'Preview' }).click();
  let sends = 0;
  await page.route('https://system.localhost:8443/api/system/tenants/secondary/emails/test', async route => { sends++; await route.abort(); });
  await page.getByRole('button', { name: 'Send test of saved template', exact: true }).click();
  await expect(page.getByText(/request failed after it started/i)).toBeVisible();
  expect(sends).toBe(1);
  await page.waitForTimeout(500);
  expect(sends).toBe(1);
});
