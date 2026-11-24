// Plan 38a (make e2e-ad): no directory password, provisioning ticket or
// signing key in zeroauthy's server log.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const work=process.env.E2E_M38A_WORK;
const log=await readFile(`${work}/server.log`,'utf8');
const creds=JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8'));
const ticket=(await readFile(`${work}/ticket`,'utf8')).trim().split('/').pop();
assert.ok(log.includes('ad connector connected'),'the server log covers the run');
for(const [name,value] of [['new password',creds.newPassword],['provisioning ticket',ticket],['admin secret',creds.admin]]){
 assert.ok(!log.includes(value),`${name} in the server log`);
}
// The mock directory's fixture password is short; check it only as a
// logged value, not as a substring of unrelated text.
assert.ok(!new RegExp(`["=: ]${creds.directoryPassword}["\\s,}]`).test(log),'directory password in the server log');
assert.ok(!/signingKey"?\s*[:=]\s*"?[A-Za-z0-9_-]{20}/.test(log),'signing key in the server log');
console.log('Plan 38a log audit: no password, ticket, admin secret or signing key in the server log');
