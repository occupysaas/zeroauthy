// Pure SDK contract checks: fetch is replaced before any request; no server/DB.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ManagementClient } from 'auth0';
test('pinned management methods use the frozen resource paths and parse JSON', async () => {
  const requests = [];
  const m = new ManagementClient({ domain: 'localhost:8443', token: 'fixture', fetch: async (url, init) => {
    requests.push({ url: String(url), method: init.method, body: init.body });
    return new Response(JSON.stringify({ sentinel: 'parsed' }), { status: 200, headers: { 'content-type': 'application/json' } });
  } });
  assert.equal((await m.tenants.settings.get()).sentinel, 'parsed');
  await m.tenants.settings.update({ friendly_name: 'fixture' });
  for (const [name, path] of [['bruteForceProtection','brute-force-protection'], ['suspiciousIpThrottling','suspicious-ip-throttling'], ['breachedPasswordDetection','breached-password-detection'], ['botDetection','bot-detection'], ['captcha','captcha']]) {
    assert.equal((await m.attackProtection[name].get()).sentinel, 'parsed');
    assert.ok(requests.at(-1).url.endsWith(`/attack-protection/${path}`));
    const patch = name === 'captcha' ? { active_provider_id: 'simple_captcha' } : {};
    await m.attackProtection[name].update(patch); assert.equal(requests.at(-1).method, 'PATCH');
    assert.deepEqual(JSON.parse(requests.at(-1).body), patch);
  }
  await m.userBlocks.listByIdentifier({ identifier: 'alice@example.test' });
  assert.equal(new URL(requests.at(-1).url).searchParams.get('identifier'), 'alice@example.test');
  await m.userBlocks.deleteByIdentifier({ identifier: 'alice@example.test' }); assert.equal(requests.at(-1).method, 'DELETE');
  await m.userBlocks.list('auth0|fixture'); assert.ok(requests.at(-1).url.endsWith('/user-blocks/auth0%7Cfixture'));
  await m.userBlocks.delete('auth0|fixture'); assert.equal(requests.at(-1).method, 'DELETE');
  await m.anomaly.blocks.checkIp('192.0.2.19'); assert.ok(requests.at(-1).url.endsWith('/anomaly/blocks/ips/192.0.2.19'));
  await m.anomaly.blocks.unblockIp('192.0.2.19'); assert.equal(requests.at(-1).method, 'DELETE');
});
