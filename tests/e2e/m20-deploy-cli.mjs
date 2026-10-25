import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { load as parseYaml, dump as dumpYaml } from 'js-yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const e2e = path.join(root, 'tests/e2e');
const work = process.env.E2E_M20_WORK;
const format = process.env.E2E_M20_FORMAT;
const mode = process.env.E2E_M20_MODE;
assert.ok(['yaml', 'directory'].includes(format));
assert.ok(['generated', 'preserved'].includes(mode));
const secrets = ['e2e-cli-admin-secret-not-for-production', 'e2e-cli-target-admin-secret-not-for-production', 'e2e-cli-fixture-secret-not-for-production'];
const emailSecret = 'm21-deploy-private-provider-secret';
const sourceConfig = { ...JSON.parse(await readFile(process.env.E2E_M20_CONFIG, 'utf8')), AUTH0_CLIENT_SECRET: secrets[0], AUTH0_EXPORT_IDENTIFIERS: false };
const targetConfig = { ...sourceConfig, AUTH0_DOMAIN: 'target.cli.e2e.test', AUTH0_CLIENT_ID: 'e2e-cli-target-admin', AUTH0_CLIENT_SECRET: secrets[1] };
const bin = path.join(e2e, 'node_modules/.bin/a0deploy');
const comparator = args => spawnSync('go', ['run', './tests/e2e/deploy-cli', ...args], { cwd: root, encoding: 'utf8' });
function checkedCompare(source, target) {
  const result = comparator(['compare', '--source', source, '--target', target, '--format', format, '--manifest', path.join(work, 'manifest.json')]);
  assert.ok(result.stdout, 'comparator produced no redacted report');
  return JSON.parse(result.stdout);
}
const version = spawnSync(bin, ['--version'], { encoding: 'utf8' });
assert.equal(version.status, 0); assert.equal(version.stdout.trim(), '9.1.0');
const manifest = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/manifest.json'), 'utf8'));
const excluded = JSON.parse(comparator(['exclusions', '--manifest', 'tests/e2e/deploy-cli/manifest.json']).stdout);
// These handlers require APIs outside the implemented roadmap. Their absence
// is reported explicitly, never counted as a successful migration.
const unavailable = manifest.resources.filter(entry => entry.status === 'tool-unsupported').map(entry => entry.name);
sourceConfig.AUTH0_EXCLUDED = excluded;
targetConfig.AUTH0_EXCLUDED = sourceConfig.AUTH0_EXCLUDED;
assert.ok(unavailable.every(name => excluded.includes(name)), 'manifest must explicitly exclude unavailable handlers');
await writeFile(path.join(work, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });
for (const [name, config] of [['source', sourceConfig], ['target', targetConfig]]) await writeFile(path.join(work, `${name}.json`), JSON.stringify(config), { mode: 0o600 });
function deploy(command, config, input) {
  const result = spawnSync(bin, [command, '--config_file', path.join(work, `${config}.json`), ...(command === 'export' ? ['--format', format, '--output_folder', input] : ['--input_file', input]), '--proxy_url', 'http://127.0.0.1:8098'], { cwd: e2e, encoding: 'utf8', env: { ...process.env, AUTH0_ALLOW_DELETE: 'false' } });
  // Tool failure logs can contain complete application payloads. Keep them in
  // restricted scratch storage and emit only operation/status to the console.
  if (result.status !== 0) {
    let log = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    for (const secret of secrets) log = log.replaceAll(secret, '[redacted]');
    execFileSync('python3', ['-c', 'import sys; from pathlib import Path; p=Path(sys.argv[1]); p.write_text(sys.stdin.read()); p.chmod(0o600)', path.join(work, 'deploy-error.log')], { input: log });
    const diagnostic = log.split('\n').filter(line => /Status code:|\"message\":|Problem running command/.test(line)).join(' ');
    throw new Error(`pinned CLI ${command} failed (exit ${result.status}): ${diagnostic}`);
  }
}
async function exportTo(config, name) {
  const folder = path.join(work, name);
  await mkdir(folder, { recursive: true });
  deploy('export', config, folder);
  return format === 'yaml' ? path.join(folder, 'tenant.yaml') : folder;
}
async function assertNoEmailSecrets(exportPath) {
  const files = format === 'yaml'
    ? [await readFile(exportPath, 'utf8')]
    : await Promise.all((await readdir(exportPath, { recursive: true })).map(name => readFile(path.join(exportPath, name), 'utf8').catch(() => '')));
  const joined = files.join('\n');
  assert.equal(joined.includes(emailSecret), false, 'public deploy export contains provider credential');
  assert.equal(joined.includes('********'), false, 'public deploy export contains a credential mask');
}
function request(config, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', port: 8443, servername: config.AUTH0_DOMAIN, path: route, method, headers: { host: config.AUTH0_DOMAIN, 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) } }, res => {
      let data = ''; res.setEncoding('utf8'); res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) { reject(new Error(`local ${method} ${route.split('?')[0]} returned ${res.statusCode}`)); return; }
        resolve(data ? JSON.parse(data) : null);
      });
    });
    req.on('error', reject); if (body !== undefined) req.write(JSON.stringify(body)); req.end();
  });
}
const tokens = new Map();
async function api(config, method, route, body) {
  if (!tokens.has(config.AUTH0_DOMAIN)) {
    const token = await request(config, 'POST', '/oauth/token', { grant_type: 'client_credentials', client_id: config.AUTH0_CLIENT_ID, client_secret: config.AUTH0_CLIENT_SECRET, audience: `https://${config.AUTH0_DOMAIN}/api/v2/` });
    tokens.set(config.AUTH0_DOMAIN, token.access_token);
  }
  return request(config, method, `/api/v2/${route}`, body, tokens.get(config.AUTH0_DOMAIN));
}
async function inventory(config, expectFailure = false) {
  const rows = await api(config, 'GET', 'resource-servers');
  const file = path.join(work, 'inventory.json'); await writeFile(file, JSON.stringify(rows), { mode: 0o600 });
  const result = comparator(['preflight-inventory', '--input', file]);
  assert.equal(result.status === 0, !expectFailure, 'pre-export collision preflight result');
}
const sourcePath = format === 'yaml' ? path.join(work, 'source-export/tenant.yaml') : path.join(work, 'source-export');
if (process.env.E2E_M20_PHASE === 'prepare') {
  const registrySource = await readFile(path.join(e2e, 'node_modules/auth0-deploy-cli/lib/tools/auth0/handlers/index.js'), 'utf8');
  const body = registrySource.match(/const auth0ApiHandlers = \{([\s\S]*?)\n\};/);
  assert.ok(body);
  const names = [...body[1].matchAll(/^\s{4}(\w+),?\s*$/gm)].map(m => m[1]);
  if (body[1].includes('clientAuthCredentialsPre')) names.push('clientAuthCredentialsPre');
  const registryPath = path.join(work, 'registry.json'); await writeFile(registryPath, JSON.stringify([...new Set(names)].sort()));
  assert.equal(comparator(['validate-manifest', '--registry', registryPath, '--manifest', 'tests/e2e/deploy-cli/manifest.json']).status, 0);
  await inventory(sourceConfig);
  // Provider credentials are written from this isolated test process only.
  // They are never placed in a checked-in seed or recovered by GET/export.
  await api(sourceConfig, 'POST', 'emails/provider', { name: 'sendgrid', enabled: true, default_from_address: 'deploy@example.test', credentials: { api_key: emailSecret } });
  await api(sourceConfig, 'POST', 'email-templates', { template: 'verify_email', enabled: true, subject: 'Deploy verify', body: '<p>Verify {{ user.email | escape }}</p>' });
  const publicProvider = await api(sourceConfig, 'GET', 'emails/provider');
  assert.equal(JSON.stringify(publicProvider).includes(emailSecret), false, 'provider read returned its private credential');
  assert.equal(JSON.stringify(publicProvider).includes('********'), false, 'provider read returned a credential mask');
  const collision = await api(sourceConfig, 'POST', 'resource-servers', { name: 'Auth0 Management API', identifier: 'https://collision.cli.e2e.test' });
  await inventory(sourceConfig, true);
  await api(sourceConfig, 'DELETE', `resource-servers/${collision.id}`);
  const sourcePublicExport = await exportTo('source', 'source-export');
  await assertNoEmailSecrets(sourcePublicExport);
  if (mode === 'preserved') {
    await writeFile(path.join(work, 'source.json'), JSON.stringify({ ...sourceConfig, AUTH0_EXPORT_IDENTIFIERS: true }), { mode: 0o600 });
    const bootstrapExport = await exportTo('source', 'bootstrap-export');
    await writeFile(path.join(work, 'source.json'), JSON.stringify(sourceConfig), { mode: 0o600 });
    const fixture = parseYaml(await readFile(path.join(e2e, 'deploy-cli/seed.yaml'), 'utf8'));
    const bootstrap = path.join(work, 'bootstrap.yaml');
    await writeFile(bootstrap, dumpYaml({ tenants: [fixture.tenants[1]] }), { mode: 0o600 });
    const credentials = path.join(work, 'credentials.json');
    await writeFile(credentials, JSON.stringify({ 'e2e-cli-fixture': secrets[2] }), { mode: 0o600 });
    const args = ['migration', 'bootstrap', '--config', 'tests/e2e/config.yaml', '--input', bootstrapExport, '--format', format, '--bootstrap-seed', bootstrap, '--credentials-file', credentials];
    for (const suffix of [['--check'], [], []]) {
      const result = spawnSync(process.env.E2E_M20_BINARY, [...args, ...suffix], { cwd: root, encoding: 'utf8', env: { ...process.env, ZEROAUTHY_SEED_MODE: 'create_only' } });
      assert.equal(result.status, 0, `offline bootstrap failed: ${result.stderr?.replaceAll(secrets[2], '[redacted]')}`);
    }
  }
  process.exit(0);
}
const baseline = checkedCompare(sourcePath, sourcePath);
assert.equal(baseline.equivalent, true, JSON.stringify(baseline)); assert.ok(baseline.counts.every(row => row.source > 0));
const exportClients = async config => (await api(config, 'GET', 'clients')).filter(c => c.name === 'E2E deploy fixture');
const original = (await exportClients(sourceConfig))[0];
const toolBefore = await api(targetConfig, 'GET', `clients/${targetConfig.AUTH0_CLIENT_ID}`);
// This target-side private configuration is the explicit reinjection point.
// The subsequent CLI import omits credentials and its PATCH must preserve it.
  await api(targetConfig, 'POST', 'emails/provider', { name: 'sendgrid', enabled: false, default_from_address: 'target-before-import@example.test', credentials: { api_key: emailSecret } });
assertPrivateEmailCredential();
deploy('import', 'target', sourcePath);
function assertPrivateEmailCredential() {
  const result = spawnSync('go', ['test', './tests/e2e/deploy-cli', '-run', '^TestE2EPrivateEmailProviderCredentialAfterImport$', '-count=1'], { cwd: root, encoding: 'utf8', env: { ...process.env, E2E_EMAIL_PRIVATE_SECRET: emailSecret } });
  assert.equal(result.status, 0, `private email credential did not survive import: ${(result.stdout + result.stderr).replaceAll(emailSecret, '[redacted]')}`);
}
assertPrivateEmailCredential();
let targetPath = await exportTo('target', 'target-first');
assert.equal(checkedCompare(sourcePath, targetPath).equivalent, true, 'first round trip differs');
const imported = (await exportClients(targetConfig))[0];
assert.equal(imported.client_id === original.client_id, mode === 'preserved');
assert.ok((imported.client_secret === original.client_secret) === (mode === 'preserved'), 'credential preservation mode mismatch');
assert.ok(imported.client_secret);
const toolAfter = await api(targetConfig, 'GET', `clients/${targetConfig.AUTH0_CLIENT_ID}`);
assert.ok(JSON.stringify(toolAfter) === JSON.stringify(toolBefore), 'deployment credential client was changed');
// Inventory the unrelated destination resource before and after import, then
// delete only this test-created record before comparing migration resources.
const extra = await api(targetConfig, 'POST', 'clients', { name: 'Target-only application', app_type: 'spa', token_endpoint_auth_method: 'none', grant_types: ['authorization_code'] });
const extraBefore = await api(targetConfig, 'GET', `clients/${extra.client_id}`);
deploy('import', 'target', sourcePath);
assert.ok(JSON.stringify(await api(targetConfig, 'GET', `clients/${extra.client_id}`)) === JSON.stringify(extraBefore), 'deletion-disabled import changed target-only resource');
await api(targetConfig, 'DELETE', `clients/${extra.client_id}`);
const repeated = (await exportClients(targetConfig))[0];
assert.equal(repeated.client_id, imported.client_id); assert.ok(repeated.client_secret === imported.client_secret, 'repeat import changed credential');
targetPath = await exportTo('target', 'target-repeat');
assert.equal(checkedCompare(sourcePath, targetPath).equivalent, true, 'repeat import differs');
await api(sourceConfig, 'PATCH', 'tenants/settings', { friendly_name: 'Updated deploy fixture' });
const grants = await api(sourceConfig, 'GET', 'client-grants');
const grant = grants.find(g => g.client_id === original.client_id);
await api(sourceConfig, 'PATCH', `client-grants/${grant.id}`, { scope: ['read:fixture'] });
const updated = await exportTo('source', 'source-updated');
assert.equal(checkedCompare(updated, targetPath).equivalent, false, 'negative scope/setting change escaped comparator');
await api(sourceConfig, 'PATCH', 'emails/provider', { enabled: false });
await api(sourceConfig, 'PATCH', 'email-templates/verify_email', { subject: 'Changed deploy verify' });
const changedEmail = await exportTo('source', 'source-email-updated');
assert.equal(checkedCompare(changedEmail, targetPath).equivalent, false, 'negative provider/template change escaped comparator');
deploy('import', 'target', changedEmail);
assertPrivateEmailCredential();
targetPath = await exportTo('target', 'target-email-updated');
assert.equal(checkedCompare(changedEmail, targetPath).equivalent, true, 'email resource update differs');
const targetProvider = await api(targetConfig, 'GET', 'emails/provider');
assert.equal(JSON.stringify(targetProvider).includes(emailSecret), false, 'target provider read returned its private credential');
assert.equal(JSON.stringify(targetProvider).includes('********'), false, 'target provider read returned a credential mask');
deploy('import', 'target', updated);
targetPath = await exportTo('target', 'target-updated');
const report = checkedCompare(updated, targetPath);
assert.equal(report.equivalent, true, 'updated round trip differs');
assert.equal((await api(targetConfig, 'GET', 'tenants/settings')).friendly_name, 'Updated deploy fixture');
const token = await request(targetConfig, 'POST', '/oauth/token', { grant_type: 'client_credentials', client_id: imported.client_id, client_secret: imported.client_secret, audience: 'https://fixture.cli.e2e.test', scope: 'read:fixture' });
assert.ok(token.access_token); assert.equal(token.scope, 'read:fixture');
const claims = JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url'));
assert.equal(claims.iss, `https://${targetConfig.AUTH0_DOMAIN}/`); assert.ok([claims.aud].flat().includes('https://fixture.cli.e2e.test'));
process.stdout.write(`Plan 20 deploy-cli: version=9.1.0 format=${format} mode=${mode} lane=local import=passed repeat=passed credentials=passed update=passed targetOnly=passed negative=detected runtime=passed counts=${JSON.stringify(report.counts)}\n`);
