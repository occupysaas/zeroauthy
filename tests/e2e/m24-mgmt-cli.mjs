// Plan 24 with the pinned Auth0 CLI 1.37.0 against the social connections
// the SDK lane created: list and show never expose provider secrets.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { noSecret } from './social/client.mjs';

const home = mkdtempSync('/tmp/za-m24-cli-');
const env = {
  PATH: process.env.PATH, HOME: home,
  HTTPS_PROXY: 'http://127.0.0.1:9198', SSL_CERT_FILE: process.env.E2E_CERT,
  AUTH0_CLI_ANALYTICS: 'false', AUTH0_CLI_AUTH_MODE: 'env',
  AUTH0_DOMAIN: 'sdk.e2e.test', AUTH0_CLIENT_ID: 'm24-admin',
  AUTH0_CLIENT_SECRET: 'm24-admin-secret-not-for-production',
};
function run(args, status = 0) {
  const r = spawnSync(process.env.AUTH0_BIN, [...args, '--no-input', '--no-color'], { env, encoding: 'utf8', timeout: 60_000 });
  assert.ok(!r.error, `${r.error}`);
  assert.equal(r.status, status, `${args.slice(0, 3).join(' ')}: ${r.stderr}`);
  try { return JSON.parse(r.stdout); } catch { return r.stdout; }
}
try {
  const all = run(['api', 'get', 'connections']);
  const social = all.filter((c) => ['google-oauth2', 'oauth2', 'oidc'].includes(c.strategy)).map((c) => c.name).sort();
  assert.deepEqual(social, ['acme-oauth', 'corp', 'google-oauth2']);
  noSecret(all);
  const corp = all.find((c) => c.name === 'corp');
  noSecret(run(['api', 'get', `connections/${corp.id}`]));
  const clients = run(['api', 'get', `connections/${corp.id}/clients`]);
  assert.deepEqual(clients.clients.map((c) => c.client_id), ['m24-spa']);
  console.log('m24 CLI: social connections listed without secrets');
} finally {
  rmSync(home, { recursive: true, force: true });
}
