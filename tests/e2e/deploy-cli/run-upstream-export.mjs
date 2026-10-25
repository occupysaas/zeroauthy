import { spawnSync } from 'node:child_process';
import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ManagementClient } from 'auth0';

// Observer-only: this entry point never imports to Auth0. It runs only when
// invoked explicitly with a protected external config and output directory.
const configPath = process.env.AUTH0_DEPLOY_CONFIG;
if (!configPath) {
  console.log(JSON.stringify({ lane: 'upstream', outcome: 'unavailable', reason: 'AUTH0_DEPLOY_CONFIG was not supplied' }));
  process.exit(0);
}
const info = await lstat(configPath);
if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077)) throw new Error('observer config must be a protected regular file');
const config = JSON.parse(await readFile(configPath, 'utf8'));
const output = process.env.AUTH0_DEPLOY_EXPORT_DIR;
const format = process.env.AUTH0_DEPLOY_FORMAT ?? 'directory';
if (!output || !['yaml', 'directory'].includes(format)) throw new Error('restricted output directory and supported format are required');
// Refuse existing output to avoid combining exports or changing permissions
// on an operator-owned tree. Raw exports and tool logs remain private.
await mkdir(output, { mode: 0o700 });
process.umask(0o077);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../..');
const management = new ManagementClient({ domain: config.AUTH0_DOMAIN, clientId: config.AUTH0_CLIENT_ID, clientSecret: config.AUTH0_CLIENT_SECRET, ...(config.AUTH0_ACCESS_TOKEN ? { token: config.AUTH0_ACCESS_TOKEN } : {}), maxRetries: 0 });
const resources = [];
for await (const row of await management.resourceServers.list()) resources.push(row);
const clients = [];
for await (const row of await management.clients.list()) clients.push(row);
const inventoryPath = path.join(output, '.inventory.json');
await writeFile(inventoryPath, JSON.stringify(resources), { mode: 0o600 });
const check = spawnSync('go', ['run', './tests/e2e/deploy-cli', 'preflight-inventory', '--input', inventoryPath], { cwd: root, encoding: 'utf8' });
if (check.status !== 0) throw new Error('upstream inventory preflight failed; raw inventory retained in restricted storage');
if (!clients.length || !resources.length) throw new Error('upstream inventory is empty; observation cannot establish a migration');
const exportPath = path.join(output, 'export');
await mkdir(exportPath, { mode: 0o700 });
const bin = path.resolve(here, '../node_modules/.bin/a0deploy');
const result = spawnSync(bin, ['export', '--config_file', configPath, '--format', format, '--output_folder', exportPath], { cwd: here, encoding: 'utf8', env: { ...process.env, AUTH0_ALLOW_DELETE: 'false' } });
await writeFile(path.join(output, '.observer.log'), `${result.stdout ?? ''}${result.stderr ?? ''}`, { mode: 0o600 });
if (result.status !== 0) throw new Error('upstream export failed; inspect restricted observer log');
console.log(JSON.stringify({ lane: 'upstream', outcome: 'exported', format, counts: { clients: clients.length, resourceServers: resources.length }, fields: { clients: [...new Set(clients.flatMap(Object.keys))].sort(), resourceServers: [...new Set(resources.flatMap(Object.keys))].sort() }, comparison: 'pending local import and re-export' }));
