// Plan 38a (make e2e-ad): the pinned Deploy CLI 9.1.0 exports the tenant
// with its ad connection and imports it back twice: the connector's
// certificates, the provisioning ticket and the live connector survive
// (connector-managed options are ignored on writes, LR38a-6).
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M38A_WORK;
const creds=JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8'));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const config={AUTH0_DOMAIN:'localhost:9565',AUTH0_CLIENT_ID:'m38a-admin',AUTH0_CLIENT_SECRET:creds.admin,AUTH0_INCLUDED_ONLY:['connections'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
await writeFile(`${work}/deploy.json`,JSON.stringify(config),{mode:0o600});
let n=0;
function a0deploy(args){const r=spawnSync(bin,[...args,'--config_file',`${work}/deploy.json`],{cwd:root,encoding:'utf8',env:process.env});
 const log=`${work}/deploy-${++n}.log`;spawnSync('sh',['-c',`cat > ${JSON.stringify(log)}`],{input:`${r.stdout??''}${r.stderr??''}`});
 if(r.status!==0)throw new Error(`a0deploy ${args[0]} exited ${r.status}; see ${path.basename(log)}`);}
async function api(route,method='GET',body){
 const t=await (await fetch('https://localhost:9565/oauth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:'m38a-admin',client_secret:creds.admin,audience:'https://localhost:9565/api/v2/'})})).json();
 const r=await fetch(`https://localhost:9565/api/v2/${route}`,{method,headers:{authorization:`Bearer ${t.access_token}`,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});
 return {status:r.status,body:await r.json().catch(()=>undefined)};
}
const {id}=JSON.parse(await readFile(`${work}/connection.json`,'utf8'));
const before=(await api(`connections/${id}`)).body;
assert.equal(before.options.certs.length,1);
await mkdir(`${work}/export`,{recursive:true});
a0deploy(['export','--format','yaml','--output_folder',`${work}/export`]);
const exported=load(await readFile(`${work}/export/tenant.yaml`,'utf8'));
const conn=exported.connections.find(c=>c.name==='corp-ad');
assert.ok(conn,'ad connection exported');assert.equal(conn.strategy,'ad');
assert.ok(!JSON.stringify(exported).includes(creds.admin),'export exposed the admin secret');
for(let i=0;i<2;i++)a0deploy(['import','--input_file',`${work}/export/tenant.yaml`]);
const after=(await api(`connections/${id}`)).body;
assert.deepEqual(after.options.certs,before.options.certs,'certificates survive the import');
assert.equal(after.options.signInEndpoint,before.options.signInEndpoint);
assert.equal(after.provisioning_ticket_url,before.provisioning_ticket_url,'ticket unchanged');
assert.equal((await api(`connections/${id}/status`)).status,200,'the connector is still connected');
console.log('Plan 38a Deploy CLI: pinned 9.1.0 export and two imports kept the connector certificates, ticket and connection');
