import { test, expect } from '@playwright/test';
const ORIGIN = 'https://localhost:8443';
const ADMIN = 'https://system.localhost:8443/admin/';
const PASSWORD = 'Operator-Password-2026';
let bearer;
async function api(path, method = 'GET', body) {
 if (!bearer) {
  const r = await fetch(`${ORIGIN}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials', client_id: 'e2e-m17-admin', client_secret: 'e2e-m17-admin-secret-not-for-production', audience: `${ORIGIN}/api/v2/` }) });
  const out = await r.json(); expect(r.status).toBe(200); bearer = out.access_token;
 }
 const r = await fetch(`${ORIGIN}/api/v2/${path}`, { method, headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
 const out = await r.json().catch(() => undefined);
 expect(r.status, JSON.stringify(out)).toBeLessThan(300); return out;
}
async function begin(page, options = {}) {
 await page.goto('https://localhost:3443/');
 await expect(page.locator('body')).toHaveAttribute('data-ready', 'true', { timeout: 20_000 });
 await page.evaluate(options => window.__za.client.loginWithRedirect({ authorizationParams: { prompt: 'login', ...options } }), options);
 await page.waitForURL(/localhost:8443\/u\/(login|signup)/);
}

test('branded combined and identifier login retain authentication and transient field behavior', async ({ page, browser }) => {
 test.setTimeout(120_000);
 test.skip(!process.env.E2E_ADMIN_SETUP_URL_M22, 'Use make e2e-branding for isolated Plan 22 fixtures');
 await api('prompts', 'PATCH', { identifier_first: false });
 await begin(page);
 await expect(page.getByText('M22 wrapper', { exact: true })).toBeVisible();
 await expect(page.getByText('APP[E2E SPA]', { exact: true })).toBeVisible();
 await expect(page.locator('#password')).toBeVisible();
 await page.fill('#username', 'alice@e2e.local'); await page.fill('#password', 'Correct-Horse-Battery-9');
 await page.locator('form[action="/u/login"] button[type=submit]').click();
 await page.waitForURL('https://localhost:3443/');
 await expect(page.locator('body')).toHaveAttribute('data-ready', 'true');
 expect(await page.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
 await api('prompts', 'PATCH', { identifier_first: true });
 const context = await browser.newContext({ ignoreHTTPSErrors: true });
 const login = await context.newPage();
 try {
  await begin(login);
  await expect(login.locator('h1')).toHaveText('M22 identify');
  await expect(login.locator('#password')).toHaveCount(0);
  await login.fill('#ulp-team', 'Team <unsafe>');
  await login.fill('#username', 'alice@e2e.local');
  await login.locator('form[action="/u/login"] button[type=submit]').click();
  await expect(login.locator('#password')).toBeVisible();
  await login.fill('#password', 'wrong-password');
  await login.locator('form[action="/u/login/password"] button[type=submit]').click();
  await expect(login.locator('[role=alert]')).toBeVisible();
  await login.locator('form[action="/u/login/identifier"] button').click();
  await expect(login.locator('#username')).toBeVisible();
  await expect(login.locator('#ulp-team')).toHaveValue('');
  await login.fill('#username', 'alice@e2e.local');
  await login.locator('form[action="/u/login"] button[type=submit]').click();
  await login.fill('#password', 'Correct-Horse-Battery-9');
  await login.locator('form[action="/u/login/password"] button[type=submit]').click();
  await login.waitForURL('https://localhost:3443/');
  await expect(login.locator('body')).toHaveAttribute('data-ready', 'true');
  expect(await login.evaluate(() => window.__za.client.isAuthenticated())).toBe(true);
 } finally { await context.close(); await api('prompts', 'PATCH', { identifier_first: false }); }
});

test('branding reaches localized signup, reset, verification, consent, logout and device pages', async ({ page }) => {
 test.setTimeout(120_000);
 test.skip(!process.env.E2E_ADMIN_SETUP_URL_M22, 'Use make e2e-branding for isolated Plan 22 fixtures');
 const branded = () => expect(page.getByText('M22 wrapper', { exact: true })).toBeVisible();
 await api('prompts/login/custom-text/fr','PUT',{login:{title:'Connexion M22'}});
 await begin(page,{ui_locales:'fr'}); await expect(page.locator('h1')).toHaveText('Connexion M22'); await branded();
 await api('prompts/login/custom-text/fr','PUT',{});
 await begin(page);
 await page.getByText('Forgot password?',{exact:true}).click(); await branded();
 await page.fill('#email','reset-me@e2e.local'); await page.locator('button[type=submit]').click(); await branded();
 await expect(page.locator('h1')).toHaveText('Check your email');
 const email=`m22-signup-${Date.now()}@e2e.local`;
 await begin(page,{screen_hint:'signup'}); await branded();
 await page.fill('#email',email); await page.fill('#password','M22-Quartz-Lantern-42!'); await page.locator('button[type=submit]').click();
 await page.waitForURL('https://localhost:3443/'); await expect(page.locator('body')).toHaveAttribute('data-ready','true');
 const user=await page.evaluate(()=>window.__za.client.getUser());
 const verification=await api('tickets/email-verification','POST',{user_id:user.sub});
 await page.goto(verification.ticket); await branded(); await expect(page.locator('h1')).toHaveText('Email Verified');
 const reset=await api('tickets/password-change','POST',{user_id:user.sub});
 await page.goto(reset.ticket); await branded();
 await page.fill('#password','M22-New-Quartz-Lantern-43!'); await page.fill('#password_confirm','M22-New-Quartz-Lantern-43!'); await page.locator('button[type=submit]').click();
 await branded(); await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto(reset.ticket); await branded(); await expect(page.locator('body')).toContainText('already been used');
 await begin(page); await page.fill('#username',email); await page.fill('#password','M22-New-Quartz-Lantern-43!'); await page.locator('button[type=submit]').click(); await page.waitForURL('https://localhost:3443/');
 await page.goto(`${ORIGIN}/activate`); await branded();
 const device=await fetch(`${ORIGIN}/oauth/device/code`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:'e2e-device',scope:'openid'})}).then(r=>r.json());
 await page.fill('#code',device.user_code); await page.locator('button[type=submit]').click();
 await page.waitForURL(/\/device\/confirmation/); await branded();
 await page.locator('button[value=cancel]').click(); await page.waitForURL(/\/device\/denied/); await branded();
 const params=new URLSearchParams({client_id:'e2e-3p-strict',response_type:'code',redirect_uri:'https://localhost:3443/strict/',scope:'openid read:things',audience:'https://api.e2e.local',state:'m22-consent',code_challenge:'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',code_challenge_method:'S256'});
 await page.goto(`${ORIGIN}/authorize?${params}`); await page.waitForURL(/\/u\/consent/); await branded();
 // Protocol form-post responses carry their own CSP, without a tenant wrapper.
 const protocol=await page.request.get(`${ORIGIN}/authorize?`+new URLSearchParams({client_id:'e2e-spa',response_type:'code',response_mode:'form_post',redirect_uri:'https://localhost:3443/',scope:'openid',state:'m22-protocol',code_challenge:'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ',code_challenge_method:'S256'}));
 const protocolHTML=await protocol.text();
 expect(protocolHTML).not.toContain('M22 wrapper'); expect(protocolHTML).toContain('<form'); expect(protocol.headers()['content-security-policy']).toContain("script-src 'nonce-");
 await page.goto(`${ORIGIN}/oidc/logout?client_id=e2e-spa`); await branded();
 await page.locator('button[type=submit]').click(); await branded(); await expect(page.locator('h1')).toHaveText('You are logged out');
 await page.goto('https://secondary.localhost:8443/u/reset-password?ticket=invalid');
 await expect(page.getByText('M22 wrapper',{exact:true})).toHaveCount(0);
});

test('identifier login keeps custom database and CAPTCHA behavior', async ({ page, browser }) => {
 test.setTimeout(90_000);
 test.skip(!process.env.E2E_ADMIN_SETUP_URL_M22, 'Use make e2e-branding for isolated Plan 22 fixtures');
 await api('prompts','PATCH',{identifier_first:true});
 const stats=()=>fetch('http://127.0.0.1:8099/stats',{headers:{authorization:'Bearer e2e-legacy-token'}}).then(r=>r.json());
 try {
  const before=await stats();
  await begin(page,{connection:'legacy-users'}); await page.fill('#username','legacy-user@e2e.local'); await page.locator('button[type=submit]').click();
  await page.waitForURL(/\/u\/login\/password/); expect((await stats()).login).toBe(before.login);
  await page.fill('#password','Legacy-Password-1'); await page.locator('form[action="/u/login/password"] button[type=submit]').click();
  await page.waitForURL('https://localhost:3443/'); await expect(page.locator('body')).toHaveAttribute('data-ready','true');
  expect((await stats()).login).toBe(before.login+1);
  const bot=await api('attack-protection/bot-detection'); const captcha=await api('attack-protection/captcha');
  const context=await browser.newContext({ignoreHTTPSErrors:true});
  try {
   await context.route('https://www.google.com/**',route=>route.fulfill({contentType:'application/javascript',body:''}));
   await api('attack-protection/captcha','PATCH',{active_provider_id:'recaptcha_v2',recaptcha_v2:{site_key:'m22-local-site',secret:'m22-local-only-secret'}});
   await api('attack-protection/bot-detection','PATCH',{challenge_password_policy:'always',monitoring_mode_enabled:false});
   const challenged=await context.newPage(); await begin(challenged); await challenged.fill('#username','alice@e2e.local'); await challenged.locator('button[type=submit]').click();
   await expect(challenged.locator('#captcha-help')).toBeVisible();
   await challenged.fill('#password','Correct-Horse-Battery-9'); await challenged.locator('form[action="/u/login/password"] button[type=submit]').click();
   await expect(challenged.locator('#captcha-help')).toBeVisible(); await expect(challenged).toHaveURL(/\/u\/login\/password/);
   await expect(challenged.getByText('M22 wrapper',{exact:true})).toBeVisible();
  } finally {
   await context.close(); await api('attack-protection/bot-detection','PATCH',{challenge_password_policy:bot.challenge_password_policy,monitoring_mode_enabled:bot.monitoring_mode_enabled});
   await api('attack-protection/captcha','PATCH',{active_provider_id:captcha.active_provider_id,recaptcha_v2:{site_key:'',secret:''}});
  }
 } finally {await api('prompts','PATCH',{identifier_first:false});}
});

test('console edits, sandbox preview and narrow/wide layouts stay isolated', async ({ page }) => {
 test.setTimeout(180_000);
 test.skip(!process.env.E2E_ADMIN_SETUP_URL_M22, 'Use make e2e-branding for isolated Plan 22 fixtures');
 await page.goto(process.env.E2E_ADMIN_SETUP_URL_M22);
 await page.fill('#password', PASSWORD); await page.fill('#password_confirm', PASSWORD); await page.click('button[type=submit]');
 await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto(ADMIN); await page.waitForURL(/\/u\/login/);
 await page.fill('#username', 'operator-m22@e2e.local'); await page.fill('#password', PASSWORD); await page.click('button[type=submit]');
 await page.waitForURL(/\/admin\/t\/e2e\/$/);
 await page.goto(`${ADMIN}t/e2e/branding`);
 await expect(page.locator('#branding-branding')).toBeEnabled();
 await page.getByRole('tab', { name: 'Theme', exact: true }).click();
 await page.locator('#theme-colors-primary_button').focus();
 await page.keyboard.press('Tab');
 await expect(page.locator('#theme-colors-primary_button_label')).toBeFocused();
 await page.fill('#theme-colors-primary_button', '#234567');
 await page.getByRole('tab', { name: 'Preview', exact: true }).click();
 await page.getByRole('button', { name: 'Render preview', exact: true }).click();
 await expect(page.locator('iframe')).toBeVisible();
 expect(await page.frameLocator('iframe').locator('button[type=submit]').evaluate(el => getComputedStyle(el).backgroundColor)).toBe('rgb(35, 69, 103)');
 await page.getByRole('tab', { name: 'Theme', exact: true }).click();
 await page.getByRole('button', { name: 'Create and activate theme' }).click();
 await expect(page.getByText('Changes saved.', { exact: true })).toBeVisible();
 await page.getByRole('button', { name: 'Delete theme', exact: true }).click();
 await expect(page.getByText('Configuration cleared.', { exact: true })).toBeVisible();
 await page.getByRole('tab', { name: 'Page template', exact: true }).click();
 const source = '<html><head>{% auth0:head %}</head><body><p>Console preview wrapper</p><img src="https://remote.example.test/image.svg" alt="Remote logo">{% auth0:widget %}</body></html>';
 await page.fill('#branding-template', source);
 await page.getByRole('button', { name: 'Save changes', exact: true }).click();
 const templatePanel=page.getByRole('tabpanel',{name:'Page template',exact:true});
 await expect(templatePanel.getByText('Changes saved.',{exact:true})).toBeVisible();
 await page.fill('#branding-template',source.replace('Console preview wrapper','Unsaved later wrapper'));
 await page.getByRole('button',{name:'Cancel',exact:true}).click();
 await expect(page.locator('#branding-template')).toHaveValue(source);
 await page.getByRole('tab', { name: 'Preview', exact: true }).click();
 await page.locator('#branding-preview-screen').focus();
 await page.keyboard.press('Tab');
 await expect(page.locator('#branding-preview-language')).toBeFocused();
 await page.keyboard.press('Tab');
 await expect(page.getByRole('button',{name:'Render preview',exact:true})).toBeFocused();
 const remoteRequests = [];
 page.on('request', request => { if (request.url().includes('remote.example.test')) remoteRequests.push(request.url()); });
 await page.getByRole('button', { name: 'Render preview', exact: true }).click();
 const iframe = page.locator('iframe');
 await expect(iframe).toBeVisible();
 expect(await iframe.getAttribute('sandbox')).toBe('');
 const frame = page.frameLocator('iframe');
 await expect(frame.getByText('Console preview wrapper', { exact: true })).toBeVisible();
 expect(await frame.locator('body').evaluate(el => getComputedStyle(el).display)).toBe('grid');
 await expect(frame.getByRole('img', { name: 'External image blocked' })).toBeVisible();
 await expect(page.locator('body')).not.toContainText('Console preview wrapper');
 expect(remoteRequests).toEqual([]);
 for (const width of [390, 1280]) {
  await page.setViewportSize({ width, height: 1600 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const frameWidth=(await iframe.boundingBox()).width;
  await expect.poll(() => frame.locator('body').evaluate(el => document.documentElement.clientWidth)).toBeGreaterThan(frameWidth - 4);
  await expect.poll(() => frame.locator('main').evaluate(el => el.getBoundingClientRect().width)).toBeGreaterThan(Math.min(370, (frameWidth - 2) * .8));
  expect(await frame.locator('body').evaluate(el => el.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath(`branding-${width}.png`), fullPage: false });
 }
 // A failed render removes the prior document and reports the server error.
 await page.route('**/branding/preview', route => route.fulfill({ status: 400, contentType: 'application/json', body: JSON.stringify({ message: 'Preview rejected' }) }));
 await page.getByRole('button', { name: 'Render preview', exact: true }).click();
 await expect(iframe).toHaveCount(0);
 await expect(page.getByText('Preview rejected', { exact: true })).toBeVisible();
 await page.unroute('**/branding/preview');
 await page.getByRole('tab', { name: 'Page template', exact: true }).click();
 await expect(page.locator('#branding-template')).toHaveValue(source);
 await page.getByRole('button', { name: 'Clear configuration', exact: true }).click();
 await expect(page.getByRole('tabpanel', { name: 'Page template', exact: true }).getByText('Configuration cleared.', { exact: true })).toBeVisible();
 // A late response from the previous tenant cannot overwrite the new editor.
 let releaseOld; const held=new Promise(resolve=>{releaseOld=resolve;});
 let signalOld; const oldStarted=new Promise(resolve=>{signalOld=resolve;});
 let holdFirst=true;
 await page.route('**/api/v2/branding',async route=>{
  if(route.request().method()!=='GET'||!holdFirst) {await route.continue();return;}
  holdFirst=false;signalOld();await held;await route.fulfill({status:200,contentType:'application/json',headers:{'access-control-allow-origin':'https://system.localhost:8443'},body:JSON.stringify({colors:{primary:'#abcdef'}})});
 });
 await page.goto(`${ADMIN}t/e2e/branding`);await oldStarted;
 await page.getByRole('button',{name:'Switch tenant'}).click();
 await page.getByRole('menuitem').filter({hasText:'secondary'}).click();
 await page.waitForURL(/\/admin\/t\/secondary\/$/);
 await page.getByRole('link',{name:'Universal Login',exact:true}).click();
 await page.waitForURL(/\/admin\/t\/secondary\/branding/);
 await expect(page.locator('#branding-branding')).toHaveValue('{}');
 releaseOld();await expect(page.locator('#branding-branding')).toHaveValue('{}');
 await page.unroute('**/api/v2/branding');

});
