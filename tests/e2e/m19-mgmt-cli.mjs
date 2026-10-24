// Pinned auth0-cli 1.37: local tenant/protection Management API compatibility.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';

const bin = process.env.AUTH0_BIN;
const cert = process.env.E2E_CERT;
assert.ok(bin && cert, 'AUTH0_BIN and E2E_CERT are required');
const domain = 'cli.e2e.test';

const env = {
  PATH: process.env.PATH,
  HOME: fs.mkdtempSync('/tmp/za-auth0-cli-'),
  HTTPS_PROXY: `http://127.0.0.1:${process.env.PROXY_PORT ?? 8098}`,
  SSL_CERT_FILE: cert,
  AUTH0_CLI_ANALYTICS: 'false',
  AUTH0_CLI_AUTH_MODE: 'env',
  AUTH0_DOMAIN: domain,
  AUTH0_CLIENT_ID: 'e2e-cli-admin',
  AUTH0_CLIENT_SECRET: 'e2e-cli-admin-secret-not-for-production',
};

function auth0(...args) {
  const result = spawnSync(bin, [...args, '--no-input', '--no-color'], { env, encoding: 'utf8', timeout: 60_000 });
  if (result.error || result.status !== 0) {
    throw new Error(`auth0 ${args.slice(0, 2).join(' ')} exited ${result.status}: ${result.error ?? result.stderr}`);
  }
  const out = result.stdout;
  try {
    return JSON.parse(out);
  } catch {
    return out + result.stderr;
  }
}

const api = (method, path, body) => auth0('api', method, path, ...(body === undefined ? [] : ['--data', JSON.stringify(body)]));
const paths = ['brute-force-protection', 'suspicious-ip-throttling', 'breached-password-detection', 'bot-detection', 'captcha'];
const saved = auth0('tenant-settings', 'show', '--json');
const policies = paths.map(p => api('GET', `attack-protection/${p}`));
try {
  api('PATCH', 'tenants/settings', { friendly_name: 'M19 CLI' });
  assert.equal(auth0('tenant-settings', 'show', '--json').friendly_name, 'M19 CLI');
  for (const [i, path] of paths.entries()) {
    const patch = i < 3 ? { enabled: false } : i === 3 ? { challenge_password_policy: 'never' } : { active_provider_id: policies[4].active_provider_id === 'auth_challenge' ? 'simple_captcha' : 'auth_challenge' };
    api('PATCH', `attack-protection/${path}`, patch);
    const value = i < 4 ? auth0('protection', path, 'show', '--json') : api('GET', `attack-protection/${path}`);
    for (const [k, v] of Object.entries(patch)) assert.deepEqual(value[k], v);
  }
  auth0('protection', 'brute-force-protection', 'update', '--max-attempts', '8', '--json');
  assert.equal(auth0('protection', 'brute-force-protection', 'show', '--json').max_attempts, 8);
  api('PATCH', 'attack-protection/suspicious-ip-throttling', { stage: { 'pre-login': { max_attempts: 9 } } });
  const nested = api('GET', 'attack-protection/suspicious-ip-throttling');
  assert.equal(nested.stage['pre-login'].max_attempts, 9);
  assert.equal(nested.stage['pre-login'].rate, policies[1].stage['pre-login'].rate);
  assert.deepEqual(nested.stage['pre-user-registration'], policies[1].stage['pre-user-registration']);
  assert.throws(() => api('GET', 'anomaly/blocks/ips/192.0.2.19'), /\b404: API request failed:/);
  assert.throws(() => api('GET', 'user-blocks/auth0%7Cm19unknown'), error => /\b404: API request failed:/.test(error.message) && error.message.includes('inexistent_user'));
  assert.throws(() => api('DELETE', 'user-blocks/auth0%7Cm19unknown'), error => /\b404: API request failed:/.test(error.message) && error.message.includes('inexistent_user'));
  assert.deepEqual(api('GET', 'user-blocks?identifier=m19-unknown%40e2e.local'), { blocked_for: [] });
  api('DELETE', 'user-blocks?identifier=m19-unknown%40e2e.local');
  api('DELETE', 'anomaly/blocks/ips/192.0.2.19');
} finally {
  api('PATCH', 'tenants/settings', { friendly_name: saved.friendly_name });
  api('PATCH', 'attack-protection/captcha', { active_provider_id: policies[4].active_provider_id });
  assert.deepEqual(api('GET', 'attack-protection/captcha'), policies[4]);
  for (let i = 0; i < 4; i++) api('PATCH', `attack-protection/${paths[i]}`, policies[i]);
  fs.rmSync(env.HOME, { recursive: true, force: true });
}
console.log('m19-mgmt-cli: tenant settings, five protection resources and unblock operations passed');
