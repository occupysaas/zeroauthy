import assert from 'node:assert/strict';
import {readFile,readdir,stat,writeFile} from 'node:fs/promises';
import {control,api,persistPublic,work,noAppleSecret} from './m39a-apple-client.mjs';
const secrets=await control('audit');
secrets.push(await readFile(process.env.E2E_APPLE_KEY,'utf8'),'apple-invalid-runtime-code-sensitive');
assert.ok(secrets.length>20,'audit must use actual exchanges, not only representative values');
assert.ok(secrets.some(s=>s.startsWith('eyJ')&&s.split('.').length===3),'actual JWTs required');
await writeFile(`${work}/private-audit-secrets.json`,JSON.stringify(secrets),{mode:0o600});
const logs=await api('logs?per_page=100');assert.equal(logs.status,200);await persistPublic('management-logs',logs.body);
const connections=await api('connections');await noAppleSecret(connections.body);await persistPublic('management-connections',connections.body);
let scanned=0;
async function scan(dir){for(const row of await readdir(dir,{withFileTypes:true})){const p=`${dir}/${row.name}`;if(row.isDirectory()){if(row.name==='playwright-results')await scan(p);continue;}if(!/\.(log|json|md|txt|html)$/.test(row.name)||row.name==='private-audit-secrets.json')continue;const raw=await readFile(p,'utf8');for(const secret of secrets.filter(Boolean)){assert.ok(!raw.includes(secret)&&!raw.includes(JSON.stringify(secret).slice(1,-1)),`sensitive runtime value leaked in ${row.name}`);}scanned++;}}
await scan(work);assert.ok(scanned>=6,'server, proxies, browser, native, CLI, Management sinks required');
assert.equal((await stat(process.env.E2E_APPLE_KEY)).mode&0o777,0o600);
assert.equal((await stat(`${work}/private-audit-secrets.json`)).mode&0o777,0o600);
console.log(`Apple secret audit: ${new Set(secrets).size} actual sensitive values absent from ${scanned} runtime artifacts and Management logs; private credentials mode 0600`);
