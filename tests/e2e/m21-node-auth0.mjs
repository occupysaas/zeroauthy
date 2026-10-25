// Plan 21 contract against the pinned node-auth0 7.4.0 ManagementClient.
import assert from 'node:assert/strict';
import { ManagementClient } from 'auth0';

const secret = 'm21-private-sdk-provider-key';
async function token(domain, scope) {
  const r = await fetch(`https://${domain}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({
    grant_type: 'client_credentials', client_id: 'e2e-m17-admin', client_secret: 'e2e-m17-admin-secret-not-for-production', audience: `https://${domain}/api/v2/`, ...(scope ? { scope } : {}),
  }) });
  const body = await r.json();
  assert.equal(r.status, 200, JSON.stringify(body));
  return body.access_token;
}
const client = async (domain, scope) => new ManagementClient({ domain, token: await token(domain, scope), maxRetries: 0 });
const m = await client('localhost:8443');
const secondary = await client('secondary.localhost:8443');
const provider = { name: 'sendgrid', enabled: true, default_from_address: 'm21@example.test', credentials: { api_key: secret } };

await m.emails.provider.create(provider);
const publicProvider = await m.emails.provider.get({ include_fields: true });
assert.equal(publicProvider.name, 'sendgrid');
assert.equal(JSON.stringify(publicProvider).includes(secret), false);
assert.equal(JSON.stringify(publicProvider).includes('********'), false);
await m.emails.provider.update({ enabled: false });
await m.emails.provider.update({ enabled: true }); // omitted credentials preserve the private secret
await assert.rejects(secondary.emails.provider.get(), e => e.statusCode === 404, 'a provider is tenant-local');

const template = { template: 'verify_email', body: '<p>Verify {{ user.email | escape }}</p>', subject: 'M21 verify', enabled: true };
await m.emailTemplates.create(template);
assert.equal((await m.emailTemplates.get('verify_email')).subject, 'M21 verify');
await m.emailTemplates.update('verify_email', { subject: 'M21 patched' });
assert.equal((await m.emailTemplates.get('verify_email')).subject, 'M21 patched');
await m.emailTemplates.set('verify_email', { ...template, subject: 'M21 replaced' });
assert.equal((await m.emailTemplates.get('verify_email')).subject, 'M21 replaced');
await assert.rejects(secondary.emailTemplates.get('verify_email'), e => e.statusCode === 404, 'templates are tenant-local');
await assert.rejects(m.emailTemplates.get('not_a_template'), e => [400, 404].includes(e.statusCode));

const reader = await client('localhost:8443', 'read:email_provider read:email_templates');
assert.equal((await reader.emails.provider.get()).name, 'sendgrid');
assert.equal((await reader.emailTemplates.get('verify_email')).subject, 'M21 replaced');
await assert.rejects(reader.emails.provider.update({ enabled: false }), e => e.statusCode === 403);
await assert.rejects(reader.emailTemplates.update('verify_email', { enabled: false }), e => e.statusCode === 403);
const wrongScope = await client('localhost:8443', 'read:tenant_settings');
await assert.rejects(wrongScope.emails.provider.get(), e => e.statusCode === 403);
await assert.rejects(wrongScope.emailTemplates.get('verify_email'), e => e.statusCode === 403);
const noWrite = await client('localhost:8443', 'update:email_provider update:email_templates');
await assert.rejects(noWrite.emails.provider.get(), e => e.statusCode === 403);

await m.emailTemplates.set('verify_email', { ...template, subject: 'Restore fixture' });
await m.emailTemplates.create({ template: 'welcome_email', body: '<p>Custom welcome</p>', subject: 'M21 welcome', enabled: true });
await m.emails.provider.delete();
await assert.rejects(m.emails.provider.get(), e => e.statusCode === 404);
await m.emailTemplates.update('verify_email', { enabled: false });
await secondary.emails.provider.create({
  name: 'smtp', enabled: true, default_from_address: 'secondary@example.test',
  credentials: { smtp_host: '127.0.0.1', smtp_port: 2526 },
});
await secondary.emailTemplates.create({ template: 'verify_email', body: '<p>Secondary verify <a href="{{ url }}">Verify</a></p>', subject: 'Secondary verify', enabled: true });
await secondary.emailTemplates.create({ template: 'welcome_email', body: '<p>Secondary welcome</p>', subject: 'Secondary welcome', enabled: true });
assert.equal((await secondary.emails.provider.get()).name, 'smtp');
console.log('m21-node-auth0: provider/template CRUD, redaction, scopes, errors and tenant isolation passed');
