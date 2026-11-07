// Original harness. Runs unmodified MIT-licensed Deploy CLI 9.1.0 handlers,
// with the CLI's own paged client, and the lockfile's Auth0 SDK 7.4.0 against
// the local Management handlers. Each passkey field is imported, exported and
// imported again unchanged; nothing in the tool is adapted.
const path = require('node:path');
const assert = require('node:assert/strict');
const modules = process.env.ZA_DEPLOY_CLI_MODULES;
const {ManagementClient} = require(path.join(modules, 'auth0'));
assert.equal(require(path.join(modules, 'auth0-deploy-cli/package.json')).version, '9.1.0');
assert.equal(require(path.join(modules, 'auth0/package.json')).version, '7.4.0');
const tools = path.join(modules, 'auth0-deploy-cli/lib/tools/auth0');
const pagedClient = require(path.join(tools, 'client')).default;
const client = pagedClient(new ManagementClient({domain: process.argv[2], token: 'fixture-token', maxRetries: 0}));
const make = name => new (require(path.join(tools, 'handlers', name)).default)({client, config: () => false});
const grant = 'urn:okta:params:oauth:grant-type:webauthn';
const fingerprint = 'AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99';
const mobile = {
  ios: {team_id: 'ABCDE12345', app_bundle_identifier: 'com.example.passkeys'},
  android: {app_package_name: 'com.example.passkeys', sha256_cert_fingerprints: [fingerprint]},
};
const pick = (rows, key, value) => rows.find(row => row[key] === value);

(async () => {
  // clients: mobile and the passkey grant.
  await make('clients').processChanges({clients: [{
    name: 'Passkey Native', app_type: 'native', token_endpoint_auth_method: 'none', is_first_party: true,
    callbacks: ['com.example.passkeys://callback'], grant_types: ['authorization_code', 'refresh_token', grant], mobile,
  }]});
  let app = pick(await make('clients').getType(), 'name', 'Passkey Native');
  assert.ok(app, 'exported clients lack the imported application');
  assert.deepEqual(app.mobile, mobile);
  assert.ok(app.grant_types.includes(grant), `grant missing: ${app.grant_types}`);
  const changedMobile = {...mobile, ios: {...mobile.ios, team_id: 'FGHIJ67890'}};
  await make('clients').processChanges({clients: [{...structuredClone(app), mobile: changedMobile}]});
  app = pick(await make('clients').getType(), 'name', 'Passkey Native');
  assert.deepEqual(app.mobile, changedMobile);
  assert.ok(app.grant_types.includes(grant));

  // Database connections carry the passkey options. The pinned tool exports
  // strategy auth0 through its databases handler, never through connections.
  const options = {
    authentication_methods: {password: {enabled: true}, passkey: {enabled: true}},
    passkey_options: {challenge_ui: 'button', progressive_enrollment_enabled: false, local_enrollment_enabled: true},
  };
  await make('databases').processChanges({databases: [{name: 'Passkey-Users', strategy: 'auth0', options, enabled_clients: ['Passkey Native']}]});
  let db = pick(await make('databases').getType(), 'name', 'Passkey-Users');
  assert.ok(db, 'exported databases lack the imported connection');
  assert.deepEqual(db.options.authentication_methods, options.authentication_methods);
  assert.deepEqual(db.options.passkey_options, options.passkey_options);
  assert.ok(!(await make('connections').getType()).some(c => c.name === 'Passkey-Users'), 'connections handler exported a database connection');
  const changed = {...options.passkey_options, challenge_ui: 'autofill', progressive_enrollment_enabled: true};
  await make('databases').processChanges({databases: [{...structuredClone(db), options: {...db.options, passkey_options: changed}}]});
  db = pick(await make('databases').getType(), 'name', 'Passkey-Users');
  assert.deepEqual(db.options.passkey_options, changed);
  assert.deepEqual(db.options.authentication_methods, options.authentication_methods);

  // customDomains: relying_party_identifier.
  await make('customDomains').processChanges({customDomains: [{domain: 'login.passkeys.e2e.test', type: 'self_managed_certs', relying_party_identifier: 'passkeys.e2e.test'}]});
  let domain = pick(await make('customDomains').getType(), 'domain', 'login.passkeys.e2e.test');
  assert.ok(domain, 'exported custom domains lack the imported domain');
  assert.equal(domain.relying_party_identifier, 'passkeys.e2e.test');
  // Re-import the declared configuration, as a repository file holds it;
  // server-generated fields such as origin_domain_name stay out (Plan 23).
  await make('customDomains').processChanges({customDomains: [{domain: domain.domain, type: domain.type, relying_party_identifier: 'login.passkeys.e2e.test'}]});
  domain = pick(await make('customDomains').getType(), 'domain', 'login.passkeys.e2e.test');
  assert.equal(domain.relying_party_identifier, 'login.passkeys.e2e.test');

  // guardianFactors: the WebAuthn flags. Security-key user verification has
  // no Management API and so no handler (LR33b-22); it must not appear.
  for (const [roaming, platform] of [[true, true], [false, true], [true, false]]) {
    await make('guardianFactors').processChanges({guardianFactors: [{name: 'webauthn-roaming', enabled: roaming}, {name: 'webauthn-platform', enabled: platform}]});
    const factors = await make('guardianFactors').getType();
    assert.equal(pick(factors, 'name', 'webauthn-roaming').enabled, roaming);
    assert.equal(pick(factors, 'name', 'webauthn-platform').enabled, platform);
    assert.ok(!JSON.stringify(factors).includes('user_verification'));
  }
  console.log('Pinned clients, databases, customDomains and guardianFactors handlers round-trip passkey fields without adaptation');
})().catch(error => { console.error(error); process.exitCode = 1; });
