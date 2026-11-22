// Original local acceptance harness (Plan 37a); unmodified pinned Deploy CLI 9.1.0.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M37A_DEPLOY_WORK, format=process.env.E2E_M37A_FORMAT, mode=process.env.E2E_M37A_MODE;
assert.ok(['yaml','directory'].includes(format));assert.ok(['generated','preserved'].includes(mode));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const source={AUTH0_DOMAIN:'cli.e2e.test',AUTH0_CLIENT_ID:'saml-source-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37A_SOURCE_ADMIN_SECRET,AUTH0_EXCLUDED_CLIENTS:['SAML source admin','SAML target admin'],AUTH0_INCLUDED_ONLY:['clients','connections'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
const target={...source,AUTH0_DOMAIN:'target.cli.e2e.test',AUTH0_CLIENT_ID:'saml-target-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37A_TARGET_ADMIN_SECRET};
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
const cert=(await readFile(process.env.E2E_M37A_IDP_CERT,'utf8')).trim();
const addons={samlp:{audience:'urn:deploy:sp',signResponse:true,nameIdentifierFormat:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',mappings:{email:'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'}}};
const samlOptions={signInEndpoint:'https://idp.deploy.example.test/sso',signOutEndpoint:'https://idp.deploy.example.test/slo',signingCert:cert,signSAMLRequest:true,fieldsMap:{email:'mail'},idpinitiated:{enabled:false}};
if(process.env.E2E_M37A_PHASE==='prepare'){
 const client=await api(source,'POST','clients',{name:'SAML service provider',app_type:'spa',token_endpoint_auth_method:'none',grant_types:['authorization_code'],callbacks:['https://sp.deploy.example.test/acs'],addons});
 await api(source,'POST','connections',{name:'corp-saml',strategy:'samlp',enabled_clients:[client.client_id],options:samlOptions});
 await writeFile(path.join(work,'original.json'),JSON.stringify(client),{mode:0o600});
 await publicExport('source','source-export');
 if(mode==='preserved'){
  await writeFile(path.join(work,'source.json'),JSON.stringify({...source,AUTH0_EXPORT_IDENTIFIERS:true,AUTH0_INCLUDED_ONLY:['clients']}),{mode:0o600});const bootstrapPath=await publicExport('source','bootstrap-export');await writeFile(path.join(work,'source.json'),JSON.stringify(source),{mode:0o600});
  await writeFile(path.join(work,'client-credentials.json'),'{}',{mode:0o600});
  const args=['migration','bootstrap','--config','tests/e2e/config.yaml','--input',bootstrapPath,'--format',format,'--bootstrap-seed',process.env.E2E_M37A_TARGET_SEED,'--credentials-file',path.join(work,'client-credentials.json')];
  for(const suffix of [['--check'],[],[]])checked(process.env.E2E_M37A_BINARY,[...args,...suffix],{ZEROAUTHY_STORAGE__DSN:process.env.E2E_M37A_TARGET_DSN},'preserved bootstrap');
 }
 console.log(`SAML deploy ${mode}/${format}: prepared`);process.exit(0);
}
for(let n=0;n<2;n++)deploy('import','target',sourcePath);
const original=JSON.parse(await readFile(path.join(work,'original.json'),'utf8'));
const imported=(await api(target,'GET','clients')).find(c=>c.name===original.name);assert.ok(imported);assert.equal(imported.client_id===original.client_id,mode==='preserved');
assert.deepEqual(imported.addons,addons);
const conn=(await api(target,'GET','connections')).find(c=>c.name==='corp-saml');assert.ok(conn,'samlp connection imported');assert.equal(conn.strategy,'samlp');
// The Deploy CLI exports signingCert as base64 of the PEM and imports it
// so; the API stores what it is sent, as Auth0 does.
const pemOf=v=>v.startsWith('-----BEGIN')?v.trim():Buffer.from(v,'base64').toString('utf8').trim();
for(const [k,v] of Object.entries(samlOptions))assert.deepEqual(k==='signingCert'?pemOf(conn.options[k]):conn.options[k],v,`samlp option ${k}`);
assert.ok(Array.isArray(conn.options.thumbprints)&&conn.options.thumbprints.length===1,'thumbprints recomputed');
assert.deepEqual((await api(target,'GET',`connections/${conn.id}/clients?take=100`)).clients.map(c=>c.client_id),[imported.client_id]);
const targetPath=await publicExport('target','target-export');
function normalized(data){return {clients:data.clients.map(c=>({name:c.name,addons:c.addons})),connections:data.connections.map(c=>({name:c.name,strategy:c.strategy,options:c.options,enabled_clients:c.enabled_clients}))};}
assert.deepEqual(normalized(await exported(targetPath)),normalized(await exported(sourcePath)));
console.log(`SAML deploy ${mode}/${format}: pinned 9.1.0 export/import/reimport/export passed`);
