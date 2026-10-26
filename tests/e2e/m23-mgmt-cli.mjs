// Pinned Auth0 CLI 1.37.0 uses its real high-level domains commands.
// The diagnostic operation alone needs the raw API command.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { publish, noSecret } from './domains/client.mjs';

const home = mkdtempSync('/tmp/za-m23-cli-');
const env = {
  PATH: process.env.PATH, HOME: home,
  HTTPS_PROXY: 'http://127.0.0.1:9098', SSL_CERT_FILE: process.env.E2E_CERT,
  AUTH0_CLI_ANALYTICS: 'false', AUTH0_CLI_AUTH_MODE: 'env',
  AUTH0_DOMAIN: 'cli.e2e.test', AUTH0_CLIENT_ID: 'm23-admin',
  AUTH0_CLIENT_SECRET: 'm23-admin-secret-not-for-production',
};
function run(args, status = 0) {
  const r = spawnSync(process.env.AUTH0_BIN, [...args, '--no-input', '--no-color'], {
    env, encoding: 'utf8', timeout: 60_000,
  });
  assert.ok(!r.error, `${r.error}`);
  assert.equal(r.status, status, `${args.slice(0, 3).join(' ')}: ${r.stderr}`);
  try { return JSON.parse(r.stdout); } catch { return r.stdout; }
}
try {
  const d = run(['domains', 'create', '--domain', 'cli.domains.e2e.test', '--type', 'self', '--policy', 'recommended', '--metadata', '{}', '--json']);
  const id = d.custom_domain_id;
  assert.ok(id); assert.equal(d.status, 'pending_verification');
  run(['domains', 'default', 'set', d.domain, '--json'], 1);
  await publish(d);
  const verified = run(['domains', 'verify', id, '--json']);
  assert.equal(verified.status, 'ready'); assert.ok(verified.cname_api_key);
  noSecret(run(['domains', 'show', id, '--json']));
  noSecret(run(['domains', 'list', '--json']));
  noSecret(run(['domains', 'verify', id, '--json']));
  const updated = run(['domains', 'update', id, '--policy', 'recommended', '--ip-header', 'x-azure-clientip', '--metadata', '{"team":"CLI"}', '--json']);
  assert.equal(updated.domain_metadata.team, 'CLI');
  assert.equal(run(['domains', 'default', 'set', d.domain, '--json']).domain, d.domain);
  assert.equal(run(['domains', 'default', 'show', '--json']).domain, d.domain);
  // The CLI retries rate limits internally; the SDK lane separately asserts
  // the immediate 429. Wait for a genuinely admitted diagnostic here.
  await new Promise(resolve => setTimeout(resolve, 30_100));
  const diagnostic = run(['api', 'POST', `custom-domains/${id}/test`]);
  assert.equal(diagnostic.success, false);
  assert.equal(run(['domains', 'default', 'set', 'cli.e2e.test', '--json']).domain, 'cli.e2e.test');
  run(['domains', 'delete', id, '--force']);
  run(['domains', 'show', id, '--json'], 1);
  console.log('m23-mgmt-cli: eight high-level domain operations plus raw diagnostic; one-time key, canonical reset and deletion passed');
} finally {
  rmSync(home, { recursive: true, force: true });
}
