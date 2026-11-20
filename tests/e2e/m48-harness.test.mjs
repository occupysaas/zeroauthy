// Failure-path tests for the actual acceptance privacy helpers. No server needed.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp,writeFile,mkdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {audit,assertRefreshTokenChanged} from './m48-node-auth0.mjs';
const sinks=['server.log','browser-console.log','cli.log','stored-sinks.jsonl'];
async function fixture(t){const dir=await mkdtemp(path.join(tmpdir(),'m48-audit-'));t.after(()=>rm(dir,{recursive:true,force:true}));await writeFile(path.join(dir,'private-values.jsonl'),JSON.stringify('throwaway-audit-sentinel')+'\n',{mode:0o600});return dir;}
test('audit fails when a required sink is missing',async t=>{const dir=await fixture(t);for(const sink of sinks.slice(1))await writeFile(path.join(dir,sink),'');await assert.rejects(audit(dir),{code:'ENOENT'});});
test('audit fails when a required sink cannot be read as a file',async t=>{const dir=await fixture(t);for(const sink of sinks.slice(1))await writeFile(path.join(dir,sink),'');await mkdir(path.join(dir,'server.log'));await assert.rejects(audit(dir),{code:'EISDIR'});});
test('audit accepts present empty mandatory sinks',async t=>{const dir=await fixture(t);for(const sink of sinks)await writeFile(path.join(dir,sink),'');await audit(dir);});
test('failed conversion assertion never discloses its opaque token',()=>{const sentinel='synthetic-sensitive-refresh-value';let diagnostic;try{assertRefreshTokenChanged(sentinel,sentinel);}catch(error){diagnostic=String(error.stack);}assert.ok(diagnostic,'fixture must exercise failure');assert.equal(diagnostic.includes(sentinel),false,'conversion failure diagnostic must exclude token values');});
