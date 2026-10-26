import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
const home = mkdtempSync('/tmp/za-m22-cli-');
const env = { PATH: process.env.PATH, HOME: home, HTTPS_PROXY: 'http://127.0.0.1:8098', SSL_CERT_FILE: process.env.E2E_CERT, AUTH0_CLI_ANALYTICS: 'false', AUTH0_CLI_AUTH_MODE: 'env', AUTH0_DOMAIN: 'cli.e2e.test', AUTH0_CLIENT_ID: 'e2e-cli-admin', AUTH0_CLIENT_SECRET: 'e2e-cli-admin-secret-not-for-production' };
function api(method, route, body) {
 const r = spawnSync(process.env.AUTH0_BIN, ['api', method, route, ...(body === undefined ? [] : ['--data', JSON.stringify(body)]), '--no-input', '--no-color'], { env, encoding: 'utf8', timeout: 60_000 });
 assert.ok(!r.error && r.status === 0, `${method} ${route}: ${r.error ?? r.stderr}`);
 try { return JSON.parse(r.stdout); } catch { return r.stdout; }
}
try {
 assert.equal(api('PATCH', 'branding', { colors: { primary: '#456789' } }).colors.primary, '#456789');
 assert.equal(api('GET', 'branding').colors.primary, '#456789');
 const theme = api('POST', 'branding/themes', { displayName: 'M22 CLI' });
 assert.equal(api('GET', 'branding/themes/default').themeId, theme.themeId);
 assert.equal(api('PATCH', `branding/themes/${theme.themeId}`, { displayName: 'CLI updated' }).displayName, 'CLI updated');
 assert.equal(api('GET', `branding/themes/${theme.themeId}`).displayName, 'CLI updated');
 api('DELETE', `branding/themes/${theme.themeId}`);
 const source = '<html><head>{% auth0:head %}</head><body>{% auth0:widget %}</body></html>';
 api('PUT', 'branding/templates/universal-login', { template: source });
 assert.equal(api('GET', 'branding/templates/universal-login').template, source);
 api('DELETE', 'branding/templates/universal-login');
 assert.equal(api('PATCH', 'prompts', { identifier_first: true }).identifier_first, true);
 assert.equal(api('GET', 'prompts').identifier_first, true);
 api('PUT', 'prompts/login/custom-text/en', { login: { title: 'CLI login' } });
 assert.equal(api('GET', 'prompts/login/custom-text/en').login.title, 'CLI login');
 api('PUT', 'prompts/login/custom-text/en', {});
 assert.deepEqual(api('GET', 'prompts/login/custom-text/en'), {});
 api('PUT', 'prompts/login/partials', { login: { 'form-footer-start': '<p>CLI footer</p>' } });
 assert.equal(api('GET', 'prompts/login/partials').login['form-footer-start'], '<p>CLI footer</p>');
 api('PUT', 'prompts/login/partials', {});
 assert.deepEqual(api('GET', 'prompts/login/partials'), {});
 console.log('m22-mgmt-cli: all 16 branding and prompt operations passed');
} finally { rmSync(home, { recursive: true, force: true }); }
