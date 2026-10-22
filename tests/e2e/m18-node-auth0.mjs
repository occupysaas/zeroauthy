// Plan 18: the pinned node-auth0 7.4 client streams imports and downloads exports.
// Catch broken multipart handling, dropped hashes, unmasked errors and lost jobs.
import assert from 'node:assert/strict';
import { createReadStream } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { gunzipSync } from 'node:zlib';
import { ManagementClient } from 'auth0';
import { AuthenticationClient } from 'auth0/legacy';

const management = new ManagementClient({ domain: 'localhost:8443', clientId: 'e2e-m17-admin', clientSecret: 'e2e-m17-admin-secret-not-for-production' });
const auth = new AuthenticationClient({ domain: 'localhost:8443', clientId: 'e2e-node', clientSecret: 'e2e-node-secret-not-for-production' });
const fixture = JSON.parse(await readFile(new URL('fixtures/import-users.json', import.meta.url)));
const connections = await management.connections.list();
const connection = connections.data.find(c => c.name === 'Username-Password-Authentication');
assert.ok(connection);
async function completed(job) {
  for (let i = 0; i < 100; i++) {
    job = await management.jobs.get(job.id);
    if (job.status === 'completed') return job;
    assert.notEqual(job.status, 'failed', JSON.stringify(job));
    await new Promise(r => setTimeout(r, 100));
  }
  assert.fail(`job ${job.id} did not complete`);
}
const imported = await completed(await management.jobs.usersImports.create({
  users: createReadStream(new URL('fixtures/import-users.json', import.meta.url)),
  connection_id: connection.id, upsert: false, send_completion_email: false,
}));
assert.deepEqual(imported.summary, { inserted: 4, updated: 0, failed: 1, total: 5 });
const errors = await management.jobs.errors.get(imported.id);
assert.equal(errors.length, 1);
assert.equal(errors[0].user.password_hash, '*****');
assert.equal(errors[0].errors[0].code, 'PATTERN');
assert.ok(!JSON.stringify(errors).includes('invalid-secret-hash'));
for (const record of fixture.slice(0, 4)) {
  const tokens = await auth.oauth.passwordGrant({ username: record.email, password: 'Pa55w0rd!', realm: connection.name, scope: 'openid' });
  assert.ok((tokens.data ?? tokens).access_token, record.email);
}
for (const format of ['csv', 'json']) {
  const job = await completed(await management.jobs.usersExports.create({ connection_id: connection.id, format,
    fields: [{ name: 'email', export_as: 'address' }, { name: 'email_verified' }] }));
  const response = await fetch(job.location);
  assert.equal(response.status, 200);
  const text = gunzipSync(Buffer.from(await response.arrayBuffer())).toString();
  if (format === 'json') {
    const rows = text.trim().split('\n').map(line => JSON.parse(line));
    for (const record of fixture.slice(0, 4)) assert.ok(rows.some(r => r.address === record.email && r.email_verified === false));
  } else {
    const rows = text.trim().split(/\r?\n/).map(line => line.split(',').map(cell => cell.replace(/^"|"$/g, '')));
    assert.deepEqual(rows[0], ['address', 'email_verified']);
    for (const record of fixture.slice(0, 4)) assert.ok(rows.some(r => r[0] === "'" + record.email && r[1] === 'false'));
  }
  for (const record of fixture) assert.ok(!text.includes(record.password_hash ?? record.custom_password_hash.hash.value));
}
const [user] = await management.users.listUsersByEmail({ email: fixture[0].email });
await completed(await management.jobs.verificationEmail.create({ user_id: user.user_id }));
const mailDir = process.env.E2E_MAIL_DIR;
assert.ok(mailDir);
const messages = await Promise.all((await readdir(mailDir)).filter(f => f.endsWith('.eml')).map(f => readFile(`${mailDir}/${f}`, 'utf8')));
assert.ok(messages.some(m => m.includes(fixture[0].email) && m.includes('/u/email-verification')));
for (const record of fixture.slice(0, 4)) {
  for (const user of await management.users.listUsersByEmail({ email: record.email })) await management.users.delete(user.user_id);
}
console.log('m18-node-auth0: import, original passwords, masked errors, CSV/JSON downloads and verification email passed');
