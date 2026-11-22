// Collection runs without any browser/server: dedicated Apple fixtures must
// neither abort the general lane nor disappear from the Apple lane.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';
const cwd=fileURLToPath(new URL('.',import.meta.url));
function collect(apple){
 const env={...process.env};delete env.E2E_M39A;delete env.E2E_M39C;if(apple)env.E2E_M39A='1';
 const r=spawnSync(process.execPath,['node_modules/@playwright/test/cli.js','test','--list','--reporter=json','--config','playwright.config.mjs'],{cwd,env,encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});
 assert.equal(r.status,0,`Playwright collection failed: ${r.stderr}`);
 const report=JSON.parse(r.stdout);assert.deepEqual(report.errors,[]);
 return report.suites;
}
test('general browser discovery succeeds without loading the Apple fixture suite',()=>{
 const suites=collect(false);
 assert.ok(suites.some(s=>s.file==='m4-spa-login.spec.mjs'),'general browser SDK suite must still be selected');
 assert.ok(!suites.some(s=>s.file==='m39a-apple.spec.mjs'));
 assert.ok(!suites.some(s=>s.file==='m39c-github.spec.mjs'),'the GitHub lane needs its own fixture');
});
test('Apple mode discovers all four required browser cases',()=>{
 const apple=collect(true).filter(s=>s.file==='m39a-apple.spec.mjs');
 assert.equal(apple.length,1);
 assert.equal(apple[0].specs.length,4);
 assert.ok(apple[0].specs.some(s=>s.title.includes('cross-site Apple form_post')));
 for(const s of apple[0].specs){assert.equal(s.tests.length,1);assert.equal(s.tests[0].expectedStatus,'passed');}
});
