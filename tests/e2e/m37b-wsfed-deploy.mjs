// Original local acceptance harness (Plan 37b); unmodified pinned Deploy CLI 9.1.0.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M37B_DEPLOY_WORK, format=process.env.E2E_M37B_FORMAT, mode=process.env.E2E_M37B_MODE;
assert.ok(['yaml','directory'].includes(format));assert.ok(['generated','preserved'].includes(mode));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const source={AUTH0_DOMAIN:'cli.e2e.test',AUTH0_CLIENT_ID:'wsfed-source-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37B_SOURCE_ADMIN_SECRET,AUTH0_EXCLUDED_CLIENTS:['WS-Fed source admin','WS-Fed target admin'],AUTH0_INCLUDED_ONLY:['clients','connections'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
const target={...source,AUTH0_DOMAIN:'target.cli.e2e.test',AUTH0_CLIENT_ID:'wsfed-target-admin',AUTH0_CLIENT_SECRET:process.env.E2E_M37B_TARGET_ADMIN_SECRET};
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
const der=(await readFile(process.env.E2E_M37B_IDP_CERT,'utf8')).split('\n').filter(l=>l&&!l.startsWith('-----')).join('');
const metadata=`<EntityDescriptor entityID="urn:deploy:sts" xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>${der}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>https://sts.deploy.example.test/adfs/ls/</Address></EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor></EntityDescriptor>`;
const addons={wsfed:{}};
const clientFields={client_aliases:['urn:deploy:rp'],form_template:'<form method="post" action="<%= callback %>"></form>'};
const adfsOptions={fedMetadataXml:metadata,entityId:'urn:deploy:adfs',user_id_attribute:'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',should_trust_email_verified_connection:'always_set_emails_as_verified',domain_aliases:['corp.deploy.example.test']};
if(process.env.E2E_M37B_PHASE==='prepare'){
 const client=await api(source,'POST','clients',{name:'WS-Fed relying party',app_type:'spa',token_endpoint_auth_method:'none',grant_types:['authorization_code'],callbacks:['https://rp.deploy.example.test/'],addons,...clientFields});
 await api(source,'POST','connections',{name:'corp-adfs',strategy:'adfs',enabled_clients:[client.client_id],options:adfsOptions});
 await writeFile(path.join(work,'original.json'),JSON.stringify(client),{mode:0o600});
 await publicExport('source','source-export');
 if(mode==='preserved'){
  await writeFile(path.join(work,'source.json'),JSON.stringify({...source,AUTH0_EXPORT_IDENTIFIERS:true,AUTH0_INCLUDED_ONLY:['clients']}),{mode:0o600});const bootstrapPath=await publicExport('source','bootstrap-export');await writeFile(path.join(work,'source.json'),JSON.stringify(source),{mode:0o600});
  await writeFile(path.join(work,'client-credentials.json'),'{}',{mode:0o600});
  const args=['migration','bootstrap','--config','tests/e2e/config.yaml','--input',bootstrapPath,'--format',format,'--bootstrap-seed',process.env.E2E_M37B_TARGET_SEED,'--credentials-file',path.join(work,'client-credentials.json')];
  for(const suffix of [['--check'],[],[]])checked(process.env.E2E_M37B_BINARY,[...args,...suffix],{ZEROAUTHY_STORAGE__DSN:process.env.E2E_M37B_TARGET_DSN},'preserved bootstrap');
 }
 console.log(`WS-Fed deploy ${mode}/${format}: prepared`);process.exit(0);
}
for(let n=0;n<2;n++)deploy('import','target',sourcePath);
const original=JSON.parse(await readFile(path.join(work,'original.json'),'utf8'));
const imported=(await api(target,'GET','clients')).find(c=>c.name===original.name);assert.ok(imported);assert.equal(imported.client_id===original.client_id,mode==='preserved');
assert.deepEqual(imported.addons,addons);
for(const [k,v] of Object.entries(clientFields))assert.deepEqual(imported[k],v,`client ${k}`);
const conn=(await api(target,'GET','connections')).find(c=>c.name==='corp-adfs');assert.ok(conn,'adfs connection imported');assert.equal(conn.strategy,'adfs');
for(const [k,v] of Object.entries(adfsOptions))assert.deepEqual(conn.options[k],v,`adfs option ${k}`);
assert.equal(conn.options.signInEndpoint,'https://sts.deploy.example.test/adfs/ls/','signInEndpoint from the metadata');
assert.ok(Array.isArray(conn.options.thumbprints)&&conn.options.thumbprints.length===1,'thumbprints recomputed');
assert.deepEqual((await api(target,'GET',`connections/${conn.id}/clients?take=100`)).clients.map(c=>c.client_id),[imported.client_id]);
const targetPath=await publicExport('target','target-export');
function normalized(data){return {clients:data.clients.map(c=>({name:c.name,addons:c.addons,client_aliases:c.client_aliases,form_template:c.form_template})),connections:data.connections.map(c=>({name:c.name,strategy:c.strategy,options:c.options,enabled_clients:c.enabled_clients}))};}
assert.deepEqual(normalized(await exported(targetPath)),normalized(await exported(sourcePath)));
console.log(`WS-Fed deploy ${mode}/${format}: pinned 9.1.0 export/import/reimport/export passed`);
