import assert from 'node:assert/strict';
import test from 'node:test';
import { getGlobalDispatcher } from 'undici';

test('importing the optional domain fixture preserves the shared fetch dispatcher', async () => {
  const before = getGlobalDispatcher();
  await import('./client.mjs');
  assert.ok(getGlobalDispatcher() === before, 'skipped domain specs must not redirect later baseline fetches');
});
