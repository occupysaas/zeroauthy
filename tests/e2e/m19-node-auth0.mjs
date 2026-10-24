// Pinned node-auth0 7.4 public methods. Requires the local SQL-backed harness.
import assert from 'node:assert/strict';
import { ManagementClient } from 'auth0';
export const management = new ManagementClient({ domain: 'localhost:8443', clientId: 'e2e-m17-admin', clientSecret: 'e2e-m17-admin-secret-not-for-production' });
const m = management;
const features = ['bruteForceProtection', 'suspiciousIpThrottling', 'breachedPasswordDetection', 'botDetection', 'captcha'];
const saved = await m.tenants.settings.get();
const snapshots = await Promise.all(features.map(k => m.attackProtection[k].get()));
try {
  await m.tenants.settings.update({ friendly_name: 'M19 SDK', session_lifetime: 48, idle_session_lifetime: 12, session_cookie: { mode: 'non-persistent' } });
  const settings = await m.tenants.settings.get();
  assert.equal(settings.friendly_name, 'M19 SDK');
  assert.equal(settings.session_lifetime, 48);
  assert.equal(settings.session_cookie.mode, 'non-persistent');
  const patches = [{ enabled: false, max_attempts: 7 }, { enabled: false, stage: { 'pre-login': { max_attempts: 8 } } }, { enabled: false }, { challenge_password_policy: 'never' }, { active_provider_id: snapshots[4].active_provider_id === 'auth_challenge' ? 'simple_captcha' : 'auth_challenge' }];
  for (const [i, key] of features.entries()) {
    await m.attackProtection[key].update(patches[i]);
    const value = await m.attackProtection[key].get();
    for (const [field, expected] of Object.entries(patches[i])) if (field !== 'stage') assert.deepEqual(value[field], expected);
  }
  const ip = await m.attackProtection.suspiciousIpThrottling.get();
  assert.equal(ip.stage['pre-login'].max_attempts, 8);
  assert.equal(ip.stage['pre-login'].rate, snapshots[1].stage['pre-login'].rate);
  assert.deepEqual(ip.stage['pre-user-registration'], snapshots[1].stage['pre-user-registration']);
  assert.deepEqual(await m.userBlocks.listByIdentifier({ identifier: 'm19-unknown@e2e.local' }), { blocked_for: [] });
  await m.userBlocks.deleteByIdentifier({ identifier: 'm19-unknown@e2e.local' });
  await assert.rejects(m.userBlocks.list('auth0|m19unknown'), e => e.statusCode === 404);
  await assert.rejects(m.userBlocks.delete('auth0|m19unknown'), e => e.statusCode === 404);
  await assert.rejects(m.anomaly.blocks.checkIp('192.0.2.19'), e => e.statusCode === 404);
  await m.anomaly.blocks.unblockIp('192.0.2.19');
  // An explicitly scoped token must not acquire the client's other permissions.
  const token = await fetch('https://localhost:8443/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'client_credentials', client_id: 'e2e-m17-admin', client_secret: 'e2e-m17-admin-secret-not-for-production', audience: 'https://localhost:8443/api/v2/', scope: 'read:tenant_settings' }) }).then(r => r.json());
  const reader = new ManagementClient({ domain: 'localhost:8443', token: token.access_token });
  assert.ok(await reader.tenants.settings.get());
  await assert.rejects(reader.tenants.settings.update({ friendly_name: 'forbidden' }), e => e.statusCode === 403);
  for (const feature of features) {
    await assert.rejects(reader.attackProtection[feature].get(), e => e.statusCode === 403);
    await assert.rejects(reader.attackProtection[feature].update({}), e => e.statusCode === 403);
  }
  await assert.rejects(reader.userBlocks.listByIdentifier({ identifier: 'm19-unknown@e2e.local' }), e => e.statusCode === 403);
  await assert.rejects(reader.userBlocks.deleteByIdentifier({ identifier: 'm19-unknown@e2e.local' }), e => e.statusCode === 403);
  await assert.rejects(reader.anomaly.blocks.checkIp('192.0.2.19'), e => e.statusCode === 403);
  await assert.rejects(reader.anomaly.blocks.unblockIp('192.0.2.19'), e => e.statusCode === 403);
} finally {
  await m.tenants.settings.update({ friendly_name: saved.friendly_name, session_lifetime: saved.session_lifetime, idle_session_lifetime: saved.idle_session_lifetime, session_cookie: saved.session_cookie });
  // Restore only the provider selector; credential objects were never changed.
  await m.attackProtection.captcha.update({ active_provider_id: snapshots[4].active_provider_id });
  assert.deepEqual(await m.attackProtection.captcha.get(), snapshots[4]);
  for (let i = 0; i < 4; i++) await m.attackProtection[features[i]].update(snapshots[i]);
}
console.log('m19-node-auth0: settings, all feature methods, nested preservation, blocks and scopes passed');
