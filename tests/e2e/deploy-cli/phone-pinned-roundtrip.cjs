// Original harness. Runs unmodified MIT-licensed Deploy CLI 9.1.0 handlers
// and the lockfile's Auth0 SDK 7.4.0 against the local Management handlers.
const path = require('node:path');
const assert = require('node:assert/strict');
const modules = process.env.ZA_DEPLOY_CLI_MODULES;
const {ManagementClient} = require(path.join(modules, 'auth0'));
assert.equal(require(path.join(modules, 'auth0-deploy-cli/package.json')).version, '9.1.0');
assert.equal(require(path.join(modules, 'auth0/package.json')).version, '7.4.0');
const client = new ManagementClient({domain: process.argv[2], token: 'fixture-token'});
const root = path.join(modules, 'auth0-deploy-cli/lib/tools/auth0/handlers');
const make = name => new (require(path.join(root, name)).default)({client, config: () => false});
(async () => {
  const name = 'attackProtection';
  const source = make(name);
  const exported = await source.getType();
  assert.equal(exported.phoneProviderProtection.type, 'default');
  exported.phoneProviderProtection = {type: 'exponential'};
  await source.processChanges({attackProtection: exported});
  const after = await make(name).getType();
  assert.equal(after.phoneProviderProtection.type, 'exponential');
  await make(name).processChanges({attackProtection: {...structuredClone(after), phoneProviderProtection: {type: 'default'}}});
  assert.deepEqual(await make(name).getType(), {...after, phoneProviderProtection: {type: 'default'}});
  for (const [handler, value] of [
    ['guardianPhoneFactorSettings', {otp_length: 7, otp_expiration_time: 330}],
    ['guardianPhoneFactorSelectedProvider', {provider: 'twilio'}],
    ['guardianPhoneFactorMessageTypes', {message_types: ['sms', 'voice']}]
  ]) {
    await make(handler).processChanges({[handler]: value});
    assert.deepEqual(await make(handler).getType(), value);
  }
  console.log('Pinned phone protection and Guardian phone handlers round-trip without adaptation');
})().catch(error => { console.error(error); process.exitCode = 1; });
