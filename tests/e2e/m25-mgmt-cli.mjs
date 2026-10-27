// Plan 25 with the pinned Auth0 CLI 1.37.0 against the social connections
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
  assert.equal(all.filter(c=>c.strategy==='waad').length,2);assert.equal(all.filter(c=>c.strategy==='windowslive').length,1);noSecret(all);
  const filtered=run(['api','get','connections','--query','strategy=waad']);assert.equal(filtered.length,2);assert.ok(filtered.every(c=>c.strategy==='waad'));
  const created=run(['api','post','connections','--data',JSON.stringify({name:'cli-personal',strategy:'windowslive',options:{client_id:'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',strategy_version:2,client_secret:'m24-upstream-secret-not-for-production'}})]);
  noSecret(created);const id=created.id;
  run(['api','patch',`connections/${id}/clients`,'--data',JSON.stringify([{client_id:'m24-spa',status:true}])]);
  assert.equal(run(['api','get',`connections/${id}/clients`]).clients[0].client_id,'m24-spa');
  noSecret(run(['api','patch',`connections/${id}`,'--data',JSON.stringify({display_name:'CLI personal'})]));
  assert.equal(run(['api','get',`connections/${id}`]).display_name,'CLI personal');
  run(['api','delete',`connections/${id}`]);run(['api','get',`connections/${id}`],1);
  console.log('m25 CLI 1.37.0: Microsoft CRUD, filtering, client enablement and redaction passed');
} finally {
  rmSync(home, { recursive: true, force: true });
}
