// Apple-only actual pinned Deploy CLI matrix. Public exports remain public;
// only private staging receives explicit signing-key reinjection.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir,cp} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import {generateKeyPairSync} from 'node:crypto';
import https from 'node:https';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {load,dump} from 'js-yaml';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const work=process.env.E2E_M39A_DEPLOY_WORK;
const format=process.env.E2E_M39A_FORMAT;
const mode=process.env.E2E_M39A_MODE;
assert.ok(['yaml','directory'].includes(format)); assert.ok(['generated','preserved'].includes(mode));
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
const source={AUTH0_DOMAIN:'cli.e2e.test',AUTH0_CLIENT_ID:'apple-source-admin',AUTH0_CLIENT_SECRET:'apple-source-fixture-secret',AUTH0_EXCLUDED_CLIENTS:['Apple source admin','Apple target admin'],AUTH0_INCLUDED_ONLY:['connections','clients'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false};
const target={...source,AUTH0_DOMAIN:'target.cli.e2e.test',AUTH0_CLIENT_ID:'apple-target-admin',AUTH0_CLIENT_SECRET:'apple-target-fixture-secret'};
for(const [name,config] of [['source',source],['target',target]]) await writeFile(path.join(work,`${name}.json`),JSON.stringify(config),{mode:0o600});
function checked(command,args,env={},label=command){
 const r=spawnSync(command,args,{cwd:root,env:{...process.env,...env},encoding:'utf8'});
 if(r.status!==0){
  writeFileSync(path.join(work,'failure.log'),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});
  throw new Error(`${label} exited ${r.status}; protected failure.log contains diagnostics`);
 }
 return r;
}

function deploy(command,config,input,expectFailure=false){
 const args=[command,'--config_file',path.join(work,`${config}.json`),'--proxy_url','http://127.0.0.1:8098',...(command==='export'?['--format',format,'--output_folder',input]:['--input_file',input])];
 if(expectFailure){const r=spawnSync(bin,args,{cwd:root,encoding:'utf8'});assert.notEqual(r.status,0,'missing-key import unexpectedly succeeded');assert.ok(/app_secret/i.test(`${r.stdout}${r.stderr}`),'uninjected connection must be refused for missing app_secret');return;}
 checked(bin,args,{},`a0deploy ${command}`);
}
function request(config,method,route,body,token){return new Promise((resolve,reject)=>{
 const req=https.request({hostname:'127.0.0.1',port:config.AUTH0_DOMAIN===source.AUTH0_DOMAIN?8443:8444,servername:config.AUTH0_DOMAIN,path:route,method,headers:{host:config.AUTH0_DOMAIN,'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{})}},res=>{
 let data='';res.setEncoding('utf8');res.on('data',s=>data+=s);res.on('end',()=>{if(res.statusCode<200||res.statusCode>=300){writeFileSync(path.join(work,'api-failure.json'),data,{mode:0o600});reject(new Error(`${method} ${route} returned ${res.statusCode}; protected api-failure.json contains diagnostics`));return;}resolve(data?JSON.parse(data):null);});});
 req.on('error',reject);if(body!==undefined)req.write(JSON.stringify(body));req.end();});}
const tokens=new Map();
async function api(config,method,route,body){if(!tokens.has(config.AUTH0_DOMAIN)){const t=await request(config,'POST','/oauth/token',{grant_type:'client_credentials',client_id:config.AUTH0_CLIENT_ID,client_secret:config.AUTH0_CLIENT_SECRET,audience:`https://${config.AUTH0_DOMAIN}/api/v2/`});tokens.set(config.AUTH0_DOMAIN,t.access_token);}return request(config,method,`/api/v2/${route}`,body,tokens.get(config.AUTH0_DOMAIN));}
async function exported(input){
 if(format==='yaml')return load(await readFile(input,'utf8'));
 const rows={};for(const resource of ['connections','clients'])rows[resource]=await Promise.all((await readdir(path.join(input,resource))).filter(f=>f.endsWith('.json')).map(async f=>JSON.parse(await readFile(path.join(input,resource,f),'utf8'))));return rows;
}
async function publicExport(config,name){const folder=path.join(work,name);await mkdir(folder,{recursive:true});deploy('export',config,folder);const input=format==='yaml'?path.join(folder,'tenant.yaml'):folder;const data=await exported(input);const c=data.connections.find(c=>c.name==='Apple-deploy');assert.ok(c);assert.equal(c.options.app_secret,undefined);assert.equal(c.options.client_secret,undefined);const key=await readFile(path.join(work,'apple.p8'),'utf8');const all=JSON.stringify(data);assert.equal(all.includes('PRIVATE KEY'),false);assert.equal(all.includes(key),false);return input;}
const sourcePath=format==='yaml'?path.join(work,'source-export','tenant.yaml'):path.join(work,'source-export');
const native={apple:{enabled:true},facebook:{enabled:false},google:{enabled:true}};
const mobile={ios:{team_id:'ABCDE12345',app_bundle_identifier:'test.acme.native'},android:{app_package_name:'test.acme.android'}};
if(process.env.E2E_M39A_PHASE==='prepare'){
 const key=generateKeyPairSync('ec',{namedCurve:'prime256v1',privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}}).privateKey;
 await writeFile(path.join(work,'apple.p8'),key,{mode:0o600});
 const client=await api(source,'POST','clients',{name:'Apple native deploy',app_type:'native',token_endpoint_auth_method:'none',grant_types:['authorization_code'],native_social_login:native,mobile});
 await api(source,'POST','connections',{name:'Apple-deploy',strategy:'apple',enabled_clients:[client.client_id],options:{client_id:'test.acme.web',team_id:'ABCDE12345',kid:'ABCDE67890',app_secret:key,name:true,email:false}});
 await writeFile(path.join(work,'original.json'),JSON.stringify(client),{mode:0o600});
 await publicExport('source','source-export');
 await writeFile(path.join(work,'federation-credentials.json'),JSON.stringify({'Apple-deploy':key}),{mode:0o600});
 if(mode==='preserved'){
  await writeFile(path.join(work,'source.json'),JSON.stringify({...source,AUTH0_EXPORT_IDENTIFIERS:true}),{mode:0o600});
  const bootstrapPath=await publicExport('source','bootstrap-export');
  await writeFile(path.join(work,'source.json'),JSON.stringify(source),{mode:0o600});
  await writeFile(path.join(work,'client-credentials.json'),'{}',{mode:0o600});
  const args=['migration','bootstrap','--config','tests/e2e/config.yaml','--input',bootstrapPath,'--format',format,'--bootstrap-seed',process.env.E2E_M39A_TARGET_SEED,'--credentials-file',path.join(work,'client-credentials.json')];
  for(const suffix of [['--check'],[],[]])checked(process.env.E2E_M39A_BINARY,[...args,...suffix],{ZEROAUTHY_STORAGE__DSN:process.env.E2E_M39A_TARGET_DSN},'offline preserved bootstrap');
 }
 console.log(`Apple deploy ${mode}/${format}: source export and bootstrap prepared`);process.exit(0);
}
// The CLI must fail creating the Apple connection without explicit reinjection.
deploy('import','target',sourcePath,true);
const stage=path.join(work,'private-stage');await cp(path.join(work,'source-export'),stage,{recursive:true});
const stagedInput=format==='yaml'?path.join(stage,'tenant.yaml'):stage;
const prepared=path.join(work,'private-connections.json');
checked(process.env.E2E_M39A_PREPARER,['prepare-federation','--source',sourcePath,'--format',format,'--credentials',path.join(work,'federation-credentials.json'),'--output',prepared]);
const rows=JSON.parse(await readFile(prepared,'utf8'));
if(format==='yaml'){const data=await exported(stagedInput);data.connections=rows;await writeFile(stagedInput,dump(data),{mode:0o600});}
else{for(const f of (await readdir(path.join(stage,'connections'))).filter(f=>f.endsWith('.json'))){const p=path.join(stage,'connections',f);const c=JSON.parse(await readFile(p,'utf8'));await writeFile(p,JSON.stringify(rows.find(r=>r.name===c.name)),{mode:0o600});}}
for(let n=0;n<2;n++)deploy('import','target',stagedInput);
const original=JSON.parse(await readFile(path.join(work,'original.json'),'utf8'));
const imported=(await api(target,'GET','clients')).find(c=>c.name===original.name);
assert.ok(imported);assert.equal(imported.client_id===original.client_id,mode==='preserved');assert.deepEqual(imported.native_social_login,native);assert.deepEqual(imported.mobile,mobile);
const connection=(await api(target,'GET','connections')).find(c=>c.name==='Apple-deploy');const enabled=await api(target,'GET',`connections/${connection.id}/clients?take=100`);assert.deepEqual(enabled.clients.map(c=>c.client_id),[imported.client_id]);assert.equal(connection.options.app_secret,undefined);assert.equal(connection.options.client_secret,undefined);
const targetPath=await publicExport('target','target-export');
function canonical(data){return {clients:data.clients.map(c=>({name:c.name,native_social_login:c.native_social_login,mobile:c.mobile})),connections:data.connections.map(c=>({name:c.name,strategy:c.strategy,options:c.options,enabled_clients:c.enabled_clients}))};}
assert.deepEqual(canonical(await exported(sourcePath)),canonical(await exported(targetPath)));
checked('go',['test','./tests/e2e/apple','-run','^TestDeployedAppleKey$','-count=1'],{},'private sealed key check');
console.log(`Apple deploy ${mode}/${format}: pinned 9.1.0 export/import/reimport/export, explicit reinjection, sealed key, client fields and public secret exclusion passed`);
