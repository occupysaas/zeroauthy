// Plan31 exercises the pinned SDK against the production application, never Auth0.
import assert from 'node:assert/strict';
import {readFile, writeFile, appendFile} from 'node:fs/promises';
import {Agent, ProxyAgent} from 'undici';
import {ManagementClient} from 'auth0';
import {ManagementClient as LegacyManagementClient} from 'auth0/legacy';
const inventory=JSON.parse(await readFile(new URL('../../internal/logrules/inventory.json',import.meta.url),'utf8'));
export const origin='https://sdk.e2e.test', tenant='logs';
export const credentials={client:'m31-admin',secret:'Plan31-Management-Secret-2026'};
export const password='Plan31-Login-Password-2026', actionSecret='Plan31-Action-Secret-2026', nestedSecret='Plan31-Nested-Password-2026', encodedSecret='Plan31-JSON-Secret-2026';
export const operatorPassword='Plan31-Operator-Password-2026', customPassword='Plan31-CustomDB-Password-2026';
export const email='logs-user@e2e.local', marker='[REDACTED]';
export const secrets=[password,actionSecret,nestedSecret,encodedSecret,operatorPassword,customPassword,credentials.secret,'Plan31-Password-Client-Secret-2026'];
export const work=process.env.E2E_M31_WORK;
export const dispatcher=new ProxyAgent('http://127.0.0.1:9198');
const local=new Agent();
export const fixtureFetch=(url,options={})=>fetch(url,{...options,dispatcher});
export const state=async()=>JSON.parse(await readFile(`${work}/private-state.json`,'utf8'));
export const saveState=f=>writeFile(`${work}/private-state.json`,JSON.stringify(f,null,2),{mode:0o600});
export async function capture(name,value){await appendFile(`${work}/monitoring.jsonl`,JSON.stringify({name,value})+'\n');return value;}
export function noSecrets(value,label){const text=typeof value==='string'?value:JSON.stringify(value);for(const secret of secrets)assert.ok(![secret,Buffer.from(secret).toString('hex'),Buffer.from(secret).toString('base64'),Buffer.from(secret).toString('base64url'),encodeURIComponent(secret)].some(variant=>text.includes(variant)),`${label} leaked representative secret index ${secrets.indexOf(secret)}`);}
export async function until(fn,label,timeout=45000){const end=Date.now()+timeout;while(Date.now()<end){const v=await fn();if(v)return v;await new Promise(r=>setTimeout(r,200));}throw Error(`timed out: ${label}`);}
let bearer;
export async function token(){if(bearer)return bearer;const r=await fixtureFetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:credentials.client,client_secret:credentials.secret,audience:`${origin}/api/v2/`})});const b=await r.json();assert.equal(r.status,200,'management token');return bearer=b.access_token;}
export async function api(path,method='GET',body){const r=await fixtureFetch(`${origin}/api/v2/${path}`,{method,headers:{authorization:`Bearer ${await token()}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const b=await r.json().catch(()=>undefined);assert.ok(r.ok,`${method} ${path}: ${r.status} ${JSON.stringify(b)}`);return b;}
export async function management(){return new ManagementClient({domain:'sdk.e2e.test',token:await token(),maxRetries:0,fetch:fixtureFetch});}
export async function built(m,id){return until(async()=>{const a=await m.actions.get(id);assert.notEqual(a.status,'failed',JSON.stringify(a.errors));return a.status==='built'&&a;},'Action build');}
export async function grant(connection='Username-Password-Authentication',username=email,pass=password){const r=await fixtureFetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'http://auth0.com/oauth/grant-type/password-realm',realm:connection,client_id:'m31-password',client_secret:'Plan31-Password-Client-Secret-2026',username,password:pass,scope:'openid'})});const b=await r.json();assert.equal(r.status,200,`password grant: ${JSON.stringify(b)}`);assert.ok(b.access_token);return b;}
export const receiver=(path='',body)=>fetch(`http://127.0.0.1:9186/${path}`,{dispatcher:local,...(body===undefined?{}:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})}).then(r=>r.json());
export const denyCode=`exports.onExecutePostLogin=async(e,a)=>{console.log('plan31-action-console',e.secrets.DIAGNOSTIC,e.user.user_metadata);console.log(JSON.stringify({client_secret:e.secrets.DIAGNOSTIC,nested:e.user.user_metadata}));a.access.deny('Plan31 troubleshooting denied');};`;
export const fixedCode=`exports.onExecutePostLogin=async(e,a)=>{console.log('plan31-action-fixed',e.secrets.DIAGNOSTIC,e.user.user_metadata);a.idToken.setCustomClaim('https://plan31.test/fixed',true);};`;

async function setup(){
 assert.equal(JSON.parse(await readFile(new URL('../../package.json',import.meta.resolve('auth0')),'utf8')).version,'7.4.0');
 const m=await management();
 const user=await m.users.create({connection:'Username-Password-Authentication',email,password,email_verified:true});
 // Five nesting levels and an embedded JSON string must stay private in every log sink.
 await m.users.update(user.user_id,{user_metadata:{a:{b:{c:{d:{password:nestedSecret}}}},encoded:JSON.stringify({nested:{client_secret:encodedSecret}}),email:'private-pii@e2e.local'}});
 const action=await m.actions.create({name:'Plan31 Troubleshooting',runtime:'node22',supported_triggers:[{id:'post-login',version:'v3'}],code:denyCode,secrets:[{name:'DIAGNOSTIC',value:actionSecret}]});await built(m,action.id);await m.actions.deploy(action.id);
 await m.actions.triggers.bindings.updateMany('post-login',{bindings:[{ref:{type:'action_id',value:action.id}}]});
 await saveState({user:user.user_id,action:action.id,started:new Date().toISOString()});
 console.log('Plan31 SDK setup: user, nested metadata, built/deployed/bound denial Action');
}
async function check(){
 const f=await state(),m=await management();
 await until(async()=>{const r=await api(`logs?q=${encodeURIComponent(`type:s AND user_id:"${f.user}"`)}&per_page=100`);return r.some(x=>x.log_id===f.success);},'success recorder flush');
 const legacy=new LegacyManagementClient({domain:'sdk.e2e.test',token:await token(),fetch:fixtureFetch});
 const page=(await legacy.logs.getAll({q:`user_id:"${f.user}"`,page:0,per_page:100,sort:'date:1',include_totals:true})).data;
 await capture('legacy.logs.getAll.page',page);assert.ok(page.logs.some(x=>x.log_id===f.failure));assert.ok(page.logs.some(x=>x.log_id===f.success));
 const modern=await m.logs.list({page:0,per_page:100,sort:'date:1'},{queryParams:{q:`user_id:"${f.user}"`}});await capture('logs.list.page',modern.data);assert.deepEqual(modern.data.map(x=>x.log_id),page.logs.map(x=>x.log_id));
 await until(async()=>{const r=(await legacy.logs.getAll({from:f.failure,take:100})).data;await capture('legacy.logs.getAll.checkpoint',r);return r.some(x=>x.log_id===f.success);},'settled checkpoint');
 const userLogs=(await legacy.users.getLogs({id:f.user,page:0,per_page:100,sort:'date:1'})).data;await capture('legacy.users.getLogs',userLogs);assert.deepEqual(userLogs.map(x=>x.log_id),page.logs.map(x=>x.log_id));
 const modernUser=await m.users.logs.list(f.user,{per_page:100,sort:'date:1'});assert.deepEqual(modernUser.data.map(x=>x.log_id),userLogs.map(x=>x.log_id));await capture('users.logs.list',modernUser.data);
 const execution=await m.actions.executions.get(f.execution);await capture('actions.executions.get',execution);assert.equal(execution.id,f.execution);
 noSecrets(execution,'SDK execution');
 // The public execution intentionally omits console; the operator console response
 // is asserted separately by the browser, while SDK links use canonical IDs.
 await m.users.update(f.user,{email});
 const custom=await m.connections.create({name:'Plan31-CustomDB',strategy:'auth0',enabled_clients:['m31-password'],options:{enabledDatabaseCustomization:true,import_mode:false,customScripts:{login:`function login(email,password,callback){console.log('plan31-customdb-console',password,JSON.stringify({nested:{password:password}}));callback(null,{user_id:'plan31-customdb-user',email:email,email_verified:true});}`}}});
 await grant(custom.name,'custom31@e2e.local',customPassword);
 f.customConnection=custom.id;await saveState(f);
 console.log('Plan31 node-auth0 7.4.0: modern and bundled legacy page/checkpoint/user logs and execution IDs; actual custom DB diagnostics');
}
async function prepareRestart(){
 const f=await state();await receiver('control',{fail:true});await grant();
 const rows=await until(async()=>{const rows=await api(`logs?q=${encodeURIComponent(`type:sepft AND user_id:"${f.user}"`)}&per_page=100`);const ids=rows.map(x=>x.log_id).filter(id=>id!==f.success);return ids.length&&rows;},'restart event persisted');
 f.restart=rows.filter(x=>x.log_id!==f.success).map(x=>x.log_id);await saveState(f);
 await until(async()=>{const {attempts}=await receiver();return f.streams.every(s=>attempts.some(x=>x.path===`/${s.format}`&&x.status===503&&x.items.length>0));},'failed delivery persisted before restart');
 const before=await receiver();for(const s of f.streams)assert.ok(!before.attempts.some(a=>a.path===`/${s.format}`&&a.status===200&&a.items.some(i=>f.restart.includes(i.log_id))),'restart event remains pending');
 console.log('Plan31 restart: three delivery failures witnessed; persisted event IDs remain pending');
}
async function verifyRestart(){
 const f=await state();await receiver('control',{fail:false});
 await until(async()=>{const {attempts}=await receiver();return f.streams.every(s=>[f.failure,f.success,...f.restart].every(id=>attempts.some(x=>x.path===`/${s.format}`&&x.status===200&&x.items.some(i=>i.log_id===id))));},'all formats replay without loss after server restart',90000);
 const {attempts}=await receiver();assert.ok(attempts.length>0);
 for(const a of attempts){assert.ok(['JSONLINES','JSONARRAY','JSONOBJECT'].some(format=>a.path===`/${format}`));for(const item of a.items){assert.match(item.log_id,/^\d{56}$/);assert.ok(['auth.login.fail','auth.login.success','management.success','auth.token_exchange.success'].includes(inventory.codes.find(c=>c.type===item.data.type)?.category),'stream category filter');noSecrets(item,'receiver');assert.ok(!JSON.stringify(item).includes('private-pii@e2e.local'));}}
 for(const s of f.streams)assert.ok(attempts.filter(a=>a.path===`/${s.format}`&&a.status===200).flatMap(a=>a.items).some(i=>i.data.type==='sapi'&&i.data.details?.response?.body?.email===marker),'recursive PII mask in delivered Management response');
 const m=await management(),today=new Date().toISOString().slice(0,10).replaceAll('-','');
 const daily=await m.stats.getDaily({from:today,to:today});await capture('stats.getDaily',daily);assert.equal(daily.length,1);
 const loginCodes=inventory.codes.filter(c=>c.stats_kind==='logins').map(c=>c.type);
 const successes=await api(`logs?q=${encodeURIComponent(`type:(${loginCodes.join(' OR ')})`)}&per_page=100`);assert.equal(successes.length,3,'browser, custom DB and restart password logins');assert.equal(daily[0].logins,successes.length,'daily stats count actual successful logins');assert.equal(daily[0].signups,0);assert.equal(daily[0].leaked_passwords,0);
 const active=await m.stats.getActiveUsersCount();await capture('stats.getActiveUsersCount',active);assert.equal(active,2,'hosted user and custom database user active');
 const legacy=new LegacyManagementClient({domain:'sdk.e2e.test',token:await token(),fetch:fixtureFetch});assert.deepEqual((await legacy.stats.getDaily({from:today,to:today})).data,daily);const legacyActive=(await legacy.stats.getActiveUsersCount()).data;await capture('legacy.stats.getActiveUsersCount',legacyActive);assert.equal(typeof legacyActive==='string'?JSON.parse(legacyActive):legacyActive,active);
 await writeFile(`${work}/acceptance.json`,JSON.stringify({failure:f.failure,success:f.success,execution:f.execution,restarted:f.restart,formats:f.streams.map(s=>s.format),daily,active,receiverAttempts:attempts.length},null,2));
 console.log('Plan31 streams: JSONLINES/JSONARRAY/JSONOBJECT filters, PII mask, persisted restart retry without loss; SDK daily and active-user counts');
}
if(process.argv[1]===import.meta.filename){const mode=process.argv[2];await ({setup,check,'prepare-restart':prepareRestart,'verify-restart':verifyRestart}[mode]??(()=>{throw Error(`unknown SDK fixture mode ${mode}`)}))();}
