// Original local acceptance harness (Plan 37c); unmodified pinned Deploy CLI 9.1.0.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M37C_DEPLOY_WORK, format=process.env.E2E_M37C_FORMAT, mode=process.env.E2E_M37C_MODE;
assert.ok(['yaml','directory'].includes(format));assert.ok(['generated','preserved'].includes(mode));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const source={AUTH0_DOMAIN:'cli.e2e.test',AUTH0_CLIENT_ID:'scim-source-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37C_SOURCE_ADMIN_SECRET,AUTH0_EXCLUDED_CLIENTS:['SCIM source admin','SCIM target admin'],AUTH0_INCLUDED_ONLY:['clients','connections'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
const target={...source,AUTH0_DOMAIN:'target.cli.e2e.test',AUTH0_CLIENT_ID:'scim-target-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37C_TARGET_ADMIN_SECRET};
for(const [name,config] of [['source',source],['target',target]])await writeFile(path.join(work,`${name}.json`),JSON.stringify(config),{mode:0o600});
let call=0;
function checked(command,args,env={},label=command){const r=spawnSync(command,args,{cwd:root,env:{...process.env,...env},encoding:'utf8'});writeFileSync(path.join(work,`tool-${++call}.log`),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});if(r.status!==0){writeFileSync(path.join(work,'failure.log'),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});throw new Error(`${label} exited ${r.status}; protected failure.log has diagnostics`);}return r;}
function deploy(command,config,input){checked(bin,[command,'--config_file',path.join(work,`${config}.json`),'--proxy_url','http://127.0.0.1:8098',...(command==='export'?['--format',format,'--output_folder',input]:['--input_file',input])],{},`a0deploy ${command}`);}
function request(config,method,route,body,token){return new Promise((resolve,reject)=>{const req=https.request({hostname:'127.0.0.1',port:config.AUTH0_DOMAIN===source.AUTH0_DOMAIN?8443:8444,servername:config.AUTH0_DOMAIN,path:route,method,headers:{host:config.AUTH0_DOMAIN,'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})}},res=>{let data='';res.setEncoding('utf8');res.on('data',s=>data+=s);res.on('end',()=>{if(res.statusCode<200||res.statusCode>=300){writeFileSync(path.join(work,'api-failure.json'),data,{mode:0o600});reject(new Error(`${method} ${route} returned ${res.statusCode}; protected api-failure.json has diagnostics`));return;}resolve(data?JSON.parse(data):null);});});req.on('error',reject);if(body!==undefined)req.write(JSON.stringify(body));req.end();});}
const tokens=new Map();
async function api(config,method,route,body){if(!tokens.has(config.AUTH0_DOMAIN)){const t=await request(config,'POST','/oauth/token',{grant_type:'client_credentials',client_id:config.AUTH0_CLIENT_ID,client_secret:config.AUTH0_CLIENT_SECRET,audience:`https://${config.AUTH0_DOMAIN}/api/v2/`});tokens.set(config.AUTH0_DOMAIN,t.access_token);}return request(config,method,`/api/v2/${route}`,body,tokens.get(config.AUTH0_DOMAIN));}
async function exported(input){if(format==='yaml')return load(await readFile(input,'utf8'));const rows={};for(const resource of ['clients','connections'])rows[resource]=await Promise.all((await readdir(path.join(input,resource)).catch(e=>{if(e.code==='ENOENT'&&resource==='connections')return [];throw e;})).filter(f=>f.endsWith('.json')).map(async f=>JSON.parse(await readFile(path.join(input,resource,f),'utf8'))));return rows;}
async function publicExport(config,name){const folder=path.join(work,name);await mkdir(folder,{recursive:true});deploy('export',config,folder);const input=format==='yaml'?path.join(folder,'tenant.yaml'):folder;const data=await exported(input);const all=JSON.stringify(data);for(const secret of [source.AUTH0_CLIENT_SECRET,target.AUTH0_CLIENT_SECRET])assert.equal(all.includes(secret),false,'export exposed admin secret');return input;}
const sourcePath=format==='yaml'?path.join(work,'source-export','tenant.yaml'):path.join(work,'source-export');
const mapping=[{auth0:'email',scim:'emails[primary eq true].value'},{auth0:'nickname',scim:'userName'},{auth0:'app_metadata.cost_center',scim:'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter'}];
const scimConfig={user_id_attribute:'userName',mapping};
const cert=await readFile(process.env.E2E_M37C_IDP_CERT,'utf8');
// samlp: exported without secrets, so the import needs nothing the export drops.
const samlOptions=(name)=>({signInEndpoint:`https://${name}.deploy.example.test/sso`,signingCert:cert,fieldsMap:{email:'mail'}});
if(process.env.E2E_M37C_PHASE==='prepare'){
 const conn=await api(source,'POST','connections',{name:'corp-saml',strategy:'samlp',options:samlOptions('corp')});
 await api(source,'POST',`connections/${conn.id}/scim-configuration`,scimConfig);
 await api(source,'POST','connections',{name:'plain-saml',strategy:'samlp',options:samlOptions('plain')});
 const input=await publicExport('source','source-export');
 const data=await exported(input);
 const c=data.connections.find(c=>c.name==='corp-saml');
 assert.deepEqual(c.scim_configuration,scimConfig,'export carries scim_configuration');
 assert.equal(data.connections.find(c=>c.name==='plain-saml').scim_configuration,undefined,'no configuration, none exported');
 if(mode==='preserved'){
  await writeFile(path.join(work,'source.json'),JSON.stringify({...source,AUTH0_EXPORT_IDENTIFIERS:true,AUTH0_INCLUDED_ONLY:['clients']}),{mode:0o600});const bootstrapPath=await publicExport('source','bootstrap-export');await writeFile(path.join(work,'source.json'),JSON.stringify(source),{mode:0o600});
  await writeFile(path.join(work,'client-credentials.json'),'{}',{mode:0o600});
  const args=['migration','bootstrap','--config','tests/e2e/config.yaml','--input',bootstrapPath,'--format',format,'--bootstrap-seed',process.env.E2E_M37C_TARGET_SEED,'--credentials-file',path.join(work,'client-credentials.json')];
  for(const suffix of [['--check'],[],[]])checked(process.env.E2E_M37C_BINARY,[...args,...suffix],{ZEROAUTHY_STORAGE__DSN:process.env.E2E_M37C_TARGET_DSN},'preserved bootstrap');
 }
 console.log(`SCIM deploy ${mode}/${format}: prepared`);process.exit(0);
}
// Import twice: the second run updates (PATCH) the configuration the first created.
for(let n=0;n<2;n++)deploy('import','target',sourcePath);
const conns=await api(target,'GET','connections');
const conn=conns.find(c=>c.name==='corp-saml');assert.ok(conn,'samlp connection imported');
const cfg=await api(target,'GET',`connections/${conn.id}/scim-configuration`);
assert.equal(cfg.user_id_attribute,'userName');assert.deepEqual(cfg.mapping,mapping);
const plain=conns.find(c=>c.name==='plain-saml');assert.ok(plain);
const list=await api(target,'GET','connections-scim-configurations?take=10');
assert.deepEqual(list.scim_configurations.map(c=>c.connection_id),[conn.id],'only the configured connection');
const targetPath=await publicExport('target','target-export');
function normalized(data){return data.connections.map(c=>({name:c.name,strategy:c.strategy,scim_configuration:c.scim_configuration})).sort((a,b)=>a.name.localeCompare(b.name));}
assert.deepEqual(normalized(await exported(targetPath)),normalized(await exported(sourcePath)));
console.log(`SCIM deploy ${mode}/${format}: pinned 9.1.0 export/import/reimport/export passed`);
