// Original local acceptance harness; unmodified pinned Deploy CLI 9.1.0.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M48_DEPLOY_WORK, format=process.env.E2E_M48_FORMAT, mode=process.env.E2E_M48_MODE;
assert.ok(['yaml','directory'].includes(format));assert.ok(['generated','preserved'].includes(mode));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const source={AUTH0_DOMAIN:'cli.e2e.test',AUTH0_CLIENT_ID:'refresh-source-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M48_SOURCE_ADMIN_SECRET,AUTH0_EXCLUDED_CLIENTS:['Refresh token source admin','Refresh token target admin'],AUTH0_INCLUDED_ONLY:['clients','resourceServers','tenant','organizations'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
const target={...source,AUTH0_DOMAIN:'target.cli.e2e.test',AUTH0_CLIENT_ID:'refresh-target-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M48_TARGET_ADMIN_SECRET};
for(const [name,config] of [['source',source],['target',target]])await writeFile(path.join(work,`${name}.json`),JSON.stringify(config),{mode:0o600});
let call=0;
function checked(command,args,env={},label=command){const r=spawnSync(command,args,{cwd:root,env:{...process.env,...env},encoding:'utf8'});writeFileSync(path.join(work,`tool-${++call}.log`),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});if(r.status!==0){writeFileSync(path.join(work,'failure.log'),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});throw new Error(`${label} exited ${r.status}; protected failure.log has diagnostics`);}return r;}
function deploy(command,config,input){checked(bin,[command,'--config_file',path.join(work,`${config}.json`),'--proxy_url','http://127.0.0.1:8098',...(command==='export'?['--format',format,'--output_folder',input]:['--input_file',input])],{},`a0deploy ${command}`);}
function request(config,method,route,body,token){return new Promise((resolve,reject)=>{const req=https.request({hostname:'127.0.0.1',port:config.AUTH0_DOMAIN===source.AUTH0_DOMAIN?8443:8444,servername:config.AUTH0_DOMAIN,path:route,method,headers:{host:config.AUTH0_DOMAIN,'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})}},res=>{let data='';res.setEncoding('utf8');res.on('data',s=>data+=s);res.on('end',()=>{if(res.statusCode<200||res.statusCode>=300){writeFileSync(path.join(work,'api-failure.json'),data,{mode:0o600});reject(new Error(`${method} ${route} returned ${res.statusCode}; protected api-failure.json has diagnostics`));return;}resolve(data?JSON.parse(data):null);});});req.on('error',reject);if(body!==undefined)req.write(JSON.stringify(body));req.end();});}
const tokens=new Map();
async function api(config,method,route,body){if(!tokens.has(config.AUTH0_DOMAIN)){const t=await request(config,'POST','/oauth/token',{grant_type:'client_credentials',client_id:config.AUTH0_CLIENT_ID,client_secret:config.AUTH0_CLIENT_SECRET,audience:`https://${config.AUTH0_DOMAIN}/api/v2/`});tokens.set(config.AUTH0_DOMAIN,t.access_token);}return request(config,method,`/api/v2/${route}`,body,tokens.get(config.AUTH0_DOMAIN));}
async function exported(input){if(format==='yaml')return load(await readFile(input,'utf8'));const rows={};for(const resource of ['clients','resourceServers','organizations'])rows[resource]=await Promise.all((await readdir(path.join(input,resource==='resourceServers'?'resource-servers':resource))).filter(f=>f.endsWith('.json')).map(async f=>JSON.parse(await readFile(path.join(input,resource==='resourceServers'?'resource-servers':resource,f),'utf8'))));rows.tenant=JSON.parse(await readFile(path.join(input,'tenant.json'),'utf8'));return rows;}
async function publicExport(config,name){const folder=path.join(work,name);await mkdir(folder,{recursive:true});deploy('export',config,folder);const input=format==='yaml'?path.join(folder,'tenant.yaml'):folder;const data=await exported(input);assert.ok(data.organizations?.some(o=>o.name==='refresh-company'),'organization missing from export; inspect private tool logs');const all=JSON.stringify(data);for(const secret of [source.AUTH0_CLIENT_SECRET,target.AUTH0_CLIENT_SECRET])assert.equal(all.includes(secret),false,'export exposed admin secret');return input;}
const sourcePath=format==='yaml'?path.join(work,'source-export','tenant.yaml'):path.join(work,'source-export');
const policy=[{audience:'https://refresh-api.example.test',scope:['read:items']}];
const quota={client_credentials:{per_hour:17,per_day:51,enforce:false}};
const pop={mechanism:'dpop',required:true,required_for:'public_clients'};
const defaults={clients:{client_credentials:{per_hour:10000,enforce:true}},organizations:{client_credentials:{per_day:20000,enforce:false}}};
if(process.env.E2E_M48_PHASE==='prepare'){
 await api(source,'POST','resource-servers',{name:'Refresh API',identifier:policy[0].audience,allow_offline_access:true,allow_online_access:true,allow_online_access_with_ephemeral_sessions:true,proof_of_possession:pop,scopes:[{value:'read:items',description:'Read items'}],skip_consent_for_verifiable_first_party_clients:true});
 const client=await api(source,'POST','clients',{name:'Refresh browser',app_type:'spa',token_endpoint_auth_method:'none',grant_types:['authorization_code','refresh_token'],is_first_party:true,require_proof_of_possession:true,token_quota:quota,refresh_token:{rotation_type:'rotating',expiration_type:'expiring',leeway:3,policies:policy}});
 await api(source,'POST','organizations',{name:'refresh-company',display_name:'Refresh company',token_quota:quota});
 await api(source,'PATCH','tenants/settings',{flags:{revoke_refresh_token_grant:true},dpop_strict_refresh_token_binding:false,default_token_quota:defaults});
 await writeFile(path.join(work,'original.json'),JSON.stringify(client),{mode:0o600});
 await publicExport('source','source-export');
 if(mode==='preserved'){
  await writeFile(path.join(work,'source.json'),JSON.stringify({...source,AUTH0_EXPORT_IDENTIFIERS:true}),{mode:0o600});const bootstrapPath=await publicExport('source','bootstrap-export');await writeFile(path.join(work,'source.json'),JSON.stringify(source),{mode:0o600});
  await writeFile(path.join(work,'client-credentials.json'),'{}',{mode:0o600});
  const args=['migration','bootstrap','--config','tests/e2e/config.yaml','--input',bootstrapPath,'--format',format,'--bootstrap-seed',process.env.E2E_M48_TARGET_SEED,'--credentials-file',path.join(work,'client-credentials.json')];
  for(const suffix of [['--check'],[],[]])checked(process.env.E2E_M48_BINARY,[...args,...suffix],{ZEROAUTHY_STORAGE__DSN:process.env.E2E_M48_TARGET_DSN},'preserved bootstrap');
 }
 console.log(`Refresh deploy ${mode}/${format}: prepared`);process.exit(0);
}
for(let n=0;n<2;n++)deploy('import','target',sourcePath);
const original=JSON.parse(await readFile(path.join(work,'original.json'),'utf8'));
const imported=(await api(target,'GET','clients')).find(c=>c.name===original.name);assert.ok(imported);assert.equal(imported.client_id===original.client_id,mode==='preserved');
assert.deepEqual(imported.refresh_token.policies,policy);assert.deepEqual(imported.token_quota,quota);assert.equal(imported.require_proof_of_possession,true);
const rs=(await api(target,'GET','resource-servers')).find(r=>r.identifier===policy[0].audience);assert.ok(rs);assert.equal(rs.allow_online_access,true);assert.equal(rs.allow_online_access_with_ephemeral_sessions,true);assert.deepEqual(rs.proof_of_possession,pop);
const orgs=await api(target,'GET','organizations');assert.deepEqual(orgs.find(o=>o.name==='refresh-company').token_quota,quota);
const settings=await api(target,'GET','tenants/settings');assert.deepEqual(settings.default_token_quota,defaults);assert.equal(settings.flags.revoke_refresh_token_grant,true);assert.equal(settings.dpop_strict_refresh_token_binding,false);
const targetPath=await publicExport('target','target-export');
function normalized(data){return {clients:data.clients.map(c=>({name:c.name,policies:c.refresh_token.policies,quota:c.token_quota,pop:c.require_proof_of_possession})),apis:data.resourceServers.map(r=>({identifier:r.identifier,online:r.allow_online_access,ephemeral:r.allow_online_access_with_ephemeral_sessions,pop:r.proof_of_possession})),organizations:data.organizations.map(o=>({name:o.name,quota:o.token_quota})),tenant:{default_token_quota:data.tenant.default_token_quota,revoke:data.tenant.flags.revoke_refresh_token_grant,strict:data.tenant.dpop_strict_refresh_token_binding}};}
assert.deepEqual(normalized(await exported(sourcePath)),normalized(await exported(targetPath)));
console.log(`Refresh deploy ${mode}/${format}: pinned 9.1.0 export/import/reimport/export passed (MRRT, quotas, online, DPoP, tenant flags)`);
