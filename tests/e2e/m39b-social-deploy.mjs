// Plan 39b: the pinned Deploy CLI exports a tenant with one connection per
// Tier 1 descriptor strategy, imports it into a fresh tenant only with each
// client secret explicitly reinjected, and a browser logs in to the imported
// tenant through the local stand-ins. An export whose scope disagrees with
// its flags is refused, naming the expected scope.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir,cp} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium} from '@playwright/test';
import {load,dump} from 'js-yaml';
import {authorization,complete} from './social/browser.mjs';
import {fixtureFetch,upstream} from './social/client.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const format=process.env.E2E_SOCIAL_FORMAT;
assert.ok(['yaml','directory'].includes(format));
const work=path.join(process.env.E2E_SOCIAL_WORK,`deploy-${format}`);
await mkdir(work,{recursive:true,mode:0o700});
const bin=path.join(root,'tests/e2e/node_modules/.bin/a0deploy');
const version=spawnSync(bin,['--version'],{encoding:'utf8'});assert.equal(version.status,0);assert.equal(version.stdout.trim(),'9.1.0');
// strategy → extra options and the effective scope returned on read.
const tier1=[['facebook',{email:true},'public_profile,email'],['linkedin',{email:true},['openid','profile','email']],['twitter',{},['tweet.read','users.read']],
 ['amazon',{postal_code:true},['profile','postal_code']],['paypal',{email:true},['openid','email']],['paypal-sandbox',{},['openid']],['salesforce',{},['id','profile']],
 ['salesforce-sandbox',{},['id','profile']],['salesforce-community',{community_base_url:'https://community.example'},['id','profile']],['yahoo',{},['openid','profile','email']],
 ['line',{email:true},['openid','profile','email']],['dropbox',{},['account_info.read']],['box',{},[]],['bitbucket',{},['account','email']],['shopify',{},[]]];
const names=tier1.map(([s])=>`dep-${s}`);
const scopeOf=Object.fromEntries(tier1.map(([s,,sc])=>[`dep-${s}`,sc]));
const tenant=(name,host)=>({AUTH0_DOMAIN:host,AUTH0_CLIENT_ID:`${name}-admin`,AUTH0_CLIENT_SECRET:`${name}-admin-secret-not-for-production`,
 AUTH0_EXCLUDED_CLIENTS:['socsource admin',`soctarget-${format} admin`],AUTH0_INCLUDED_ONLY:['connections','clients'],AUTH0_ALLOW_DELETE:false,AUTH0_EXPORT_IDENTIFIERS:false});
const source=tenant('socsource','source.e2e.test');
const target=tenant(`soctarget-${format}`,`${format}.target.e2e.test`);
for(const [name,config] of [['source',source],['target',target]])await writeFile(path.join(work,`${name}.json`),JSON.stringify(config),{mode:0o600});

function run(command,args){return spawnSync(command,args,{cwd:root,env:process.env,encoding:'utf8'});}
function checked(command,args,label){
 const r=run(command,args);
 if(r.status!==0){writeFileSync(path.join(work,'failure.log'),`${r.stdout??''}${r.stderr??''}`,{mode:0o600});throw new Error(`${label} exited ${r.status}; protected failure.log contains diagnostics`);}
 return r;
}
const deployArgs=(command,config,input)=>[command,'--config_file',path.join(work,`${config}.json`),'--proxy_url','http://127.0.0.1:9198',...(command==='export'?['--format',format,'--output_folder',input]:['--input_file',input])];
const deploy=(command,config,input)=>checked(bin,deployArgs(command,config,input),`a0deploy ${command}`);
function refused(command,args,pattern,what){
 const r=run(command,args);const out=`${r.stdout??''}${r.stderr??''}`;
 assert.notEqual(r.status,0,`${what} unexpectedly succeeded`);
 if(!pattern.test(out)){writeFileSync(path.join(work,'refusal.log'),out,{mode:0o600});assert.fail(`${what} failed without ${pattern}; protected refusal.log contains diagnostics`);}
}

const tokens=new Map();
async function api(config,method,route,body){
 const host=config.AUTH0_DOMAIN;
 if(!tokens.has(host)){
  const r=await fixtureFetch(`https://${host}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:config.AUTH0_CLIENT_ID,client_secret:config.AUTH0_CLIENT_SECRET,audience:`https://${host}/api/v2/`})});
  const t=await r.json();assert.equal(r.status,200);tokens.set(host,t.access_token);
 }
 const r=await fixtureFetch(`https://${host}/api/v2/${route}`,{method,headers:{authorization:`Bearer ${tokens.get(host)}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const text=await r.text();
 if(r.status<200||r.status>=300){writeFileSync(path.join(work,'api-failure.json'),text,{mode:0o600});throw new Error(`${method} ${route} returned ${r.status}; protected api-failure.json contains diagnostics`);}
 return text?JSON.parse(text):null;
}
async function exported(input){
 if(format==='yaml')return load(await readFile(input,'utf8'));
 const rows={};
 for(const resource of ['connections','clients'])rows[resource]=await Promise.all((await readdir(path.join(input,resource))).filter(f=>f.endsWith('.json')).map(async f=>JSON.parse(await readFile(path.join(input,resource,f),'utf8'))));
 return rows;
}
const inputOf=folder=>format==='yaml'?path.join(folder,'tenant.yaml'):folder;
// rewrite applies edit to every descriptor connection row (or only the one
// named) of a copied export.
async function rewrite(folder,edit,only){
 const pick=c=>only?c.name===only:names.includes(c.name);
 if(format==='yaml'){const p=inputOf(folder);const data=load(await readFile(p,'utf8'));data.connections=data.connections.map(c=>pick(c)?edit(c):c);await writeFile(p,dump(data),{mode:0o600});return;}
 for(const f of (await readdir(path.join(folder,'connections'))).filter(f=>f.endsWith('.json'))){const p=path.join(folder,'connections',f);const c=JSON.parse(await readFile(p,'utf8'));if(pick(c))await writeFile(p,JSON.stringify(edit(c)),{mode:0o600});}
}
async function publicExport(side,name){
 const folder=path.join(work,name);await mkdir(folder,{recursive:true});deploy('export',side,folder);
 const data=await exported(inputOf(folder));
 for(const [strategy] of tier1){
  const c=data.connections.find(c=>c.name===`dep-${strategy}`);
  assert.ok(c,`${strategy} connection exported`);assert.equal(c.strategy,strategy);assert.equal(c.options.client_secret,undefined);
  assert.deepEqual(c.options.scope,scopeOf[c.name],`${strategy} scope`);
 }
 assert.equal(JSON.stringify(data).includes(upstream.secret),false,'public export carries a provider client secret');
 return folder;
}

// Source: one SPA application and one connection per Tier 1 strategy
// (created once; the directory cell reuses them).
const existing=(await api(source,'GET','connections')).map(c=>c.name);
let app=(await api(source,'GET','clients')).find(c=>c.name==='Social deploy app');
if(!app)app=await api(source,'POST','clients',{name:'Social deploy app',app_type:'spa',token_endpoint_auth_method:'none',grant_types:['authorization_code'],callbacks:['https://callback.e2e.test/']});
for(const [strategy,extra] of tier1){
 if(existing.includes(`dep-${strategy}`))continue;
 const created=await api(source,'POST','connections',{name:`dep-${strategy}`,strategy,enabled_clients:[app.client_id],options:{client_id:upstream.id,client_secret:upstream.secret,...extra}});
 assert.deepEqual(created.options.scope,scopeOf[`dep-${strategy}`]);
}
const sourceFolder=await publicExport('source','source-export');

// Without explicit reinjection the CLI cannot create the connections.
refused(bin,deployArgs('import','target',inputOf(sourceFolder)),/client_secret/i,'import without the client secrets');
// An export edited so a scope disagrees with its flags is refused before
// the CLI runs (preparer) and by the Management API (manually reinjected).
const expected=/options\.scope must match the scope flags \(profile postal_code\)/;
const credentials=path.join(work,'federation-credentials.json');
await writeFile(credentials,JSON.stringify(Object.fromEntries(names.map(n=>[n,upstream.secret]))),{mode:0o600});
const edited=path.join(work,'edited-export');await cp(sourceFolder,edited,{recursive:true});
await rewrite(edited,c=>({...c,options:{...c.options,scope:['profile']}}),'dep-amazon');
refused(process.env.E2E_SOCIAL_PREPARER,['prepare-federation','--source',inputOf(edited),'--format',format,'--credentials',credentials,'--output',path.join(work,'edited-prepared.json')],expected,'preparing an edited Amazon scope');
await rewrite(edited,c=>({...c,options:{...c.options,client_secret:upstream.secret}}));
refused(bin,deployArgs('import','target',inputOf(edited)),expected,'importing an edited Amazon scope');
assert.equal((await api(target,'GET','connections')).some(c=>c.name==='dep-amazon'),false,'a refused import left the amazon connection');

// Explicit reinjection into a private staging copy, imported twice.
const prepared=path.join(work,'private-connections.json');
checked(process.env.E2E_SOCIAL_PREPARER,['prepare-federation','--source',inputOf(sourceFolder),'--format',format,'--credentials',credentials,'--output',prepared],'prepare-federation');
const rows=JSON.parse(await readFile(prepared,'utf8'));
const stage=path.join(work,'private-stage');await cp(sourceFolder,stage,{recursive:true});
await rewrite(stage,c=>rows.find(r=>r.name===c.name));
for(let n=0;n<2;n++)deploy('import','target',inputOf(stage));

const targetApp=(await api(target,'GET','clients')).find(c=>c.name==='Social deploy app');assert.ok(targetApp);
const targetFolder=await publicExport('target','target-export');
const canonical=d=>({clients:d.clients.map(c=>({name:c.name,app_type:c.app_type,callbacks:c.callbacks})),connections:d.connections.map(c=>({name:c.name,strategy:c.strategy,options:c.options,enabled_clients:c.enabled_clients}))});
assert.deepEqual(canonical(await exported(inputOf(targetFolder))),canonical(await exported(inputOf(sourceFolder))));

// Log in to the imported tenant through two imported connections: the
// stand-in accepts only the reinjected secret.
const host=target.AUTH0_DOMAIN;
const browser=await chromium.launch({headless:true,proxy:{server:'http://127.0.0.1:9198'},...(process.env.E2E_CHROMIUM?{executablePath:process.env.E2E_CHROMIUM}:{})});
try{
 for(const strategy of ['facebook','bitbucket']){
  const page=await (await browser.newContext({ignoreHTTPSErrors:true})).newPage();
  const flow=authorization({domain:host,client:targetApp.client_id,connection:`dep-${strategy}`});
  await page.goto(flow.url);
  const up=new URL(page.url());
  assert.equal(up.origin,'https://idp.e2e.test');assert.equal(up.searchParams.get('redirect_uri'),`https://${host}/login/callback`);
  const sub=`deployed-${format}-${strategy}`;
  await page.fill('#subject',sub);await page.getByRole('button',{name:'Allow',exact:true}).click();
  const {claims}=await complete(page,flow);
  assert.equal(claims.sub,`${strategy}|${sub}`);
  const u=await api(target,'GET',`users/${encodeURIComponent(`${strategy}|${sub}`)}`);
  assert.equal(u.identities[0].connection,`dep-${strategy}`);
 }
}finally{await browser.close();}
console.log(`Social providers deploy ${format}: pinned 9.1.0 export/import/reimport/export of ${tier1.length} Tier 1 connections, explicit reinjection, edited-scope refusal and logins passed`);
