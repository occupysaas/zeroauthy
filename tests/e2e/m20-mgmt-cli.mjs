import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
const home = mkdtempSync('/tmp/za-m20-cli-');
const env = { PATH: process.env.PATH, HOME: home, HTTPS_PROXY: 'http://127.0.0.1:8098', SSL_CERT_FILE: process.env.E2E_CERT, AUTH0_CLI_ANALYTICS: 'false', AUTH0_CLI_AUTH_MODE: 'env', AUTH0_DOMAIN: 'cli.e2e.test', AUTH0_CLIENT_ID: 'e2e-cli-admin', AUTH0_CLIENT_SECRET: 'e2e-cli-admin-secret-not-for-production' };
function api(method, route, body) {
  const result = spawnSync(process.env.AUTH0_BIN, ['api', method, route, ...(body ? ['--data', JSON.stringify(body)] : []), '--no-input', '--no-color'], { env, encoding: 'utf8', timeout: 60_000 });
  assert.ok(!result.error && result.status === 0, `auth0 api ${method} ${route} failed`);
  try { return JSON.parse(result.stdout); } catch { return result.stdout; }
}
try {
  const keys = api('GET', 'keys/signing'); const current = keys.find(k => k.current);
  assert.equal(api('GET', `keys/signing/${current.kid}`).kid, current.kid);
  assert.equal(api('POST', 'keys/signing/rotate').kid, keys.find(k => k.next).kid);
  assert.equal(api('PUT', `keys/signing/${current.kid}/revoke`).revoked, true);
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const key = { ...publicKey.export({ format: 'jwk' }), kid: 'cli-custom-m20', alg: 'RS256', use: 'sig' };
  assert.equal(api('PUT', 'keys/custom-signing', { keys: [key] }).keys[0].kid, key.kid);
  assert.equal(api('GET', 'keys/custom-signing').keys[0].kid, key.kid);
  api('DELETE', 'keys/custom-signing');
  assert.equal(api('GET', 'rules?include_totals=true').total, 0);
  assert.equal(api('GET', 'hooks?include_totals=true').total, 0);
  assert.deepEqual(api('GET', 'rules-configs'), []);
  console.log('m20-mgmt-cli: seven key endpoints and retired resource collections passed');
} finally { rmSync(home, { recursive: true, force: true }); }
