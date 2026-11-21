// Failure-path tests for the actual acceptance privacy helpers. No server needed.
import assert from 'node:assert/strict';
import {createHash, randomBytes} from 'node:crypto';
import {test} from 'node:test';
import {mkdtemp,writeFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {audit,assertRefreshTokenChanged} from './m48-node-auth0.mjs';
const sinks=['server.log','browser-console.log','cli.log','stored-sinks.jsonl'];
const sample = () => randomBytes(32).toString('base64url');
async function fixture(t, records = [{kind:'refresh_token', value:sample()}]) {
 const dir = await mkdtemp(path.join(tmpdir(), 'm48-audit-'));
 t.after(() => rm(dir, {recursive:true, force:true}));
 await writeFile(path.join(dir, 'private-values.jsonl'), records.map(record => JSON.stringify(record)).join('\n') + '\n', {mode:0o600});
 return dir;
}
test('audit fails when a required sink is missing',async t=>{const dir=await fixture(t);for(const sink of sinks.slice(1))await writeFile(path.join(dir,sink),'');await assert.rejects(audit(dir),{code:'ENOENT'});});
test('audit fails when a required sink cannot be read as a file',async t=>{const dir=await fixture(t);for(const sink of sinks.slice(1))await writeFile(path.join(dir,sink),'');await mkdir(path.join(dir,'server.log'));await assert.rejects(audit(dir),{code:'EISDIR'});});
test('audit accepts present empty mandatory sinks',async t=>{const dir=await fixture(t);for(const sink of sinks)await writeFile(path.join(dir,sink),'');await audit(dir);});
test('audit requires samples including an issued refresh token', async t => {
 for (const records of [[], [{kind:'credential', value:sample()}]]) {
  const dir = await fixture(t, records);
  for (const file of sinks) await writeFile(path.join(dir, file), '');
  await assert.rejects(audit(dir), /requires .*refresh token sample/);
 }
});
test('audit rejects a refresh-token digest alone in each mandatory sink without showing it', async t => {
 const value = sample();
 const digest = createHash('sha256').update(value).digest('hex');
 for (const sink of sinks) {
  const dir = await fixture(t, [{kind:'refresh_token', value}]);
  for (const file of sinks) await writeFile(path.join(dir, file), file === sink ? digest : '');
  let diagnostic = '';
  try { await audit(dir); } catch (error) { diagnostic = String(error.stack); }
  assert.ok(diagnostic.includes(sink), 'digest-only disclosure must identify the sink');
  assert.equal(diagnostic.includes(value) || diagnostic.includes(digest), false, 'diagnostic must exclude the token and its digest');
 }
});
test('malformed sample input fails without including its contents', async t => {
 const value = sample();
 const dir = await fixture(t);
 await writeFile(path.join(dir, 'private-values.jsonl'), value);
 for (const file of sinks) await writeFile(path.join(dir, file), '');
 let diagnostic = '';
 try { await audit(dir); } catch (error) { diagnostic = String(error.stack); }
 assert.ok(diagnostic.includes('Invalid representative sample'), 'malformed input must fail with a safe diagnostic');
 assert.equal(diagnostic.includes(value), false);
});
test('failed conversion assertion never discloses its opaque token',()=>{const sentinel='synthetic-sensitive-refresh-value';let diagnostic;try{assertRefreshTokenChanged(sentinel,sentinel);}catch(error){diagnostic=String(error.stack);}assert.ok(diagnostic,'fixture must exercise failure');assert.equal(diagnostic.includes(sentinel),false,'conversion failure diagnostic must exclude token values');});
