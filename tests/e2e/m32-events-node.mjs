// Pinned SDK acceptance, using only the local production application.
import assert from 'node:assert/strict';
import {readFile,writeFile,appendFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {Agent,ProxyAgent} from 'undici';
import {ManagementClient} from 'auth0';
export const work=process.env.E2E_M32_WORK;
export const origin='https://sdk.e2e.test';
export const password='Plan32-User-Password-2026',operatorPassword='Plan32-Operator-Password-2026';
export const webhookSecret='Plan32-Webhook-Bearer-2026',actionSecret='Plan32-Action-Secret-2026',upstreamToken='Plan32-Upstream-Token-2026';
export const credentials={client:'m32-admin',secret:'Plan32-Management-Secret-2026'};
export const email='events-user@e2e.local';
const secrets=[password,operatorPassword,webhookSecret,actionSecret,upstreamToken,credentials.secret,'Plan32-Password-Client-Secret-2026'];
const dispatcher=new ProxyAgent('http://127.0.0.1:9198'),local=new Agent();
export const fixtureFetch=(url,opts={})=>fetch(url,{...opts,dispatcher});
export const state=async()=>JSON.parse(await readFile(`${work}/private-state.json`,'utf8'));
export const saveState=f=>writeFile(`${work}/private-state.json`,JSON.stringify(f,null,2),{mode:0o600});
export async function capture(name,value){noSecrets(value,name);await appendFile(`${work}/responses.jsonl`,JSON.stringify({name,value})+'\n');return value;}
export function noSecrets(value,label,extra=[]){const text=typeof value==='string'?value:JSON.stringify(value);for(const [i,secret] of [...secrets,...extra].entries()){assert.ok(![secret,Buffer.from(secret).toString('hex'),Buffer.from(secret).toString('base64'),Buffer.from(secret).toString('base64url'),encodeURIComponent(secret)].some(v=>text.includes(v)),`${label}: leaked representative secret ${i}`);}}
export function validate(event){const r=spawnSync(`${work}/event-validator`,[],{input:JSON.stringify(event)+'\n',encoding:'utf8'});assert.equal(r.status,0,`frozen event schema: ${r.stderr}`);noSecrets(event,'CloudEvent');}
export async function until(fn,label,timeout=90000){const end=Date.now()+timeout;while(Date.now()<end){const value=await fn();if(value)return value;await new Promise(r=>setTimeout(r,200));}throw Error(`timed out: ${label}`);}
let bearer;
export async function token(){if(bearer)return bearer;const r=await fixtureFetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:credentials.client,client_secret:credentials.secret,audience:`${origin}/api/v2/`})});const b=await r.json();assert.equal(r.status,200);bearer=b.access_token;await appendFile(`${work}/private-tokens.jsonl`,JSON.stringify(bearer)+'\n',{mode:0o600});return bearer;}
export async function api(path,method='GET',body){const r=await fixtureFetch(`${origin}/api/v2/${path}`,{method,headers:{authorization:`Bearer ${await token()}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});const value=await r.json().catch(()=>undefined);assert.ok(r.ok,`${method} ${path}: ${r.status} ${JSON.stringify(value)}`);return capture(path,value??null);}
export async function management(){return new ManagementClient({domain:'sdk.e2e.test',token:await token(),maxRetries:0,fetch:fixtureFetch});}
export const receiver=(path='',body)=>fetch(`https://127.0.0.1:9186/${path}`,{dispatcher:local,...(body===undefined?{}:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})}).then(r=>r.json());
export async function built(m,id){return until(async()=>{const a=await m.actions.get(id);assert.notEqual(a.status,'failed',JSON.stringify(a.errors));return a.status==='built'&&a;},'Action build');}
export const throwingCode=`exports.onExecuteEventStream=async(event,api)=>{console.log('plan32-action-received',event.message.id,event.message.type,event.secrets.DIAGNOSTIC);throw new Error('plan32-action-failure '+event.secrets.DIAGNOSTIC);};`;
export const fixedCode=`exports.onExecuteEventStream=async(event,api)=>{console.log('plan32-action-fixed',event.message.id,event.message.type,event.secrets.DIAGNOSTIC);api.cache.set('plan32-last',event.message.id);};`;
export function webhook(path='/sync'){return {type:'webhook',configuration:{webhook_endpoint:`https://127.0.0.1:9186${path}`,webhook_authorization:{method:'bearer',token:webhookSecret}}};}
export async function failed(m,id,count=1){return until(async()=>{const page=await m.eventStreams.deliveries.list(id,{take:100});await capture('SDK deliveries',page.data);return page.data.length>=count&&page.data;},'failed deliveries');}
export async function cleared(m,id){await until(async()=>!(await m.eventStreams.deliveries.list(id)).data.length,'failed delivery removed');}
export async function snapshotSourceHash(user){
 const r=spawnSync(`${work}/event-validator`,['seed-source',work,user,upstreamToken],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);
 const hashes=JSON.parse(r.stdout);assert.ok(hashes.length&&hashes.every(h=>h.startsWith('$argon2id$')),'stored credential and sealed provider-token positive controls');
 await writeFile(`${work}/private-source-hashes.json`,JSON.stringify(hashes),{mode:0o600});
}

async function setup(){
 assert.equal(JSON.parse(await readFile(new URL('../../package.json',import.meta.resolve('auth0')),'utf8')).version,'7.4.0');
 const m=await management();
 await m.connections.create({name:'fixture-upstream',strategy:'google-oauth2',options:{client_id:'fixture-provider',client_secret:upstreamToken},enabled_clients:[]});
 const stream=await m.eventStreams.create({name:'Plan32 sync',subscriptions:['user.created','user.updated','user.deleted'].map(event_type=>({event_type})),destination:webhook()});await capture('SDK create',stream);
 await saveState({sync:stream.id});
 console.log('Plan32 setup: SDK 7.4.0 creates sync stream before browser signup');
}
async function sdk(){
 const m=await management(),f=await state();
 const created=await m.eventStreams.create({name:'Plan32 SDK',subscriptions:[{event_type:'user.updated'}],destination:webhook('/sdk')});await capture('SDK create second',created);
 assert.ok((await m.eventStreams.list()).data.some(s=>s.id===created.id));assert.equal((await m.eventStreams.get(created.id)).id,created.id);
 const updated=await m.eventStreams.update(created.id,{name:'Plan32 SDK updated'});assert.equal(updated.name,'Plan32 SDK updated');await capture('SDK update',updated);
 const test=await m.eventStreams.test(created.id,{event_type:'user.updated'});await capture('SDK test',test);assert.equal(test.status,'success');assert.equal(test.event.a0purpose,'test');validate(test.event);
 await receiver('control',{path:'/sdk',status:500});
 const user=await m.users.create({connection:'Username-Password-Authentication',email:'sdk-events@e2e.local',password});
 await m.users.update(user.user_id,{user_metadata:{sdk:1}});await m.users.update(user.user_id,{user_metadata:{sdk:2}});
 const rows=await failed(m,created.id,2);for(const row of rows){validate(row.event);assert.equal(row.attempts.length,4);assert.ok(row.attempts.every(a=>a.error_message==='http_5xx: 500'));}
 const detail=await m.eventStreams.deliveries.getHistory(created.id,rows[0].id);assert.equal(detail.id,rows[0].id);await capture('SDK delivery get',detail);
 await receiver('control',{path:'/sdk',status:200});await m.eventStreams.redeliveries.createById(created.id,rows[0].id);
 await until(async()=>!(await m.eventStreams.deliveries.list(created.id)).data.some(r=>r.id===rows[0].id),'SDK single redelivery');
 await m.eventStreams.redeliveries.create(created.id,{});await cleared(m,created.id);
 await m.eventStreams.delete(created.id);assert.ok(!(await m.eventStreams.list()).data.some(s=>s.id===created.id));
 f.sdkFailures=rows.map(r=>r.id);await saveState(f);
 console.log('Plan32 SDK: CRUD/test/deliveries/get/single+batch redelivery passed');
}
// A minimal SSE transport parser, independent of the production cursor codec.
export async function sse({last,from}={}){
 const abort=new AbortController();const response=await fixtureFetch(`${origin}/api/v2/events?event_type=user.updated${from?'&from='+encodeURIComponent(from):''}`,{headers:{authorization:`Bearer ${await token()}`,...(last?{'Last-Event-ID':last}:{})},signal:abort.signal});assert.equal(response.status,200);assert.match(response.headers.get('content-type'),/text\/event-stream/);
 const events=[];let buffer='',failure;
 const pump=(async()=>{try{for await(const chunk of response.body){buffer+=Buffer.from(chunk).toString();let index;while((index=buffer.indexOf('\n\n'))>=0){const block=buffer.slice(0,index);buffer=buffer.slice(index+2);const data=block.split('\n').find(l=>l.startsWith('data: '));if(data){const value=JSON.parse(data.slice(6));if(value.event){validate(value.event);assert.equal(value.event.a0stream,undefined);events.push(value);await capture('SSE',value);}}}}}catch(e){if(!abort.signal.aborted)failure=e;}})();
 return {events,async wait(count){await until(()=>{if(failure)throw failure;return events.length>=count;},'SSE events');},async close(){abort.abort();await pump;}};
}
async function resume(){
 const m=await management();const user=await m.users.create({connection:'Username-Password-Authentication',email:'sse-events@e2e.local',password});
 const first=await sse();await m.users.update(user.user_id,{user_metadata:{step:1}});await first.wait(1);await first.close();assert.equal(first.events.length,1);const offset=first.events[0].offset;
 await m.users.update(user.user_id,{user_metadata:{step:2}});await m.users.update(user.user_id,{user_metadata:{step:3}});
 const second=await sse({last:offset,from:'invalid-header-must-win'});await second.wait(2);await second.close();assert.equal(second.events.length,2);const all=[...first.events,...second.events];assert.equal(new Set(all.map(x=>x.event.id)).size,3);assert.deepEqual(all.map(x=>x.event.data.object.user_metadata.step),[1,2,3]);
 await writeFile(`${work}/sse-result.json`,JSON.stringify({events:all.map(x=>x.event.id),resumed:true,noGaps:true,noDuplicates:true}));console.log('Plan32 SSE: Last-Event-ID wins, resume without gaps or duplicates');
}
async function audit(){
 const names=['responses.jsonl','browser-responses.jsonl','browser-console.jsonl','receiver.jsonl','receiver.log','server.log','migrate.log','bootstrap.stderr','proxy.log','cli.jsonl','event-rows.jsonl','sse-result.json'];
 const hashes=JSON.parse(await readFile(`${work}/private-source-hashes.json`,'utf8'));assert.ok(hashes.length,'source credential positive control');const actualTokens=(await readFile(`${work}/private-tokens.jsonl`,'utf8')).trim().split('\n').map(JSON.parse);assert.ok(actualTokens.length);
 let bytes=0;for(const name of names){const text=await readFile(`${work}/${name}`,'utf8');bytes+=text.length;noSecrets(text,name,[...hashes,...actualTokens]);}
 const rows=(await readFile(`${work}/event-rows.jsonl`,'utf8')).trim().split('\n').map(JSON.parse);assert.ok(rows.some(r=>r.table==='tenant_events'));assert.ok(rows.some(r=>r.table==='event_streams'));assert.ok(rows.some(r=>r.table==='event_deliveries'),'keep failed delivery fixture to audit every table');
 for(const row of rows.filter(r=>r.table==='tenant_events'))validate(JSON.parse(row.value.body));
 await writeFile(`${work}/privacy-audit.json`,JSON.stringify({passed:true,audited:names,bytes,sourceHashPositiveControl:hashes.length,actualTokensChecked:new Set(actualTokens).size,sql:'SELECT * FROM tenant_events; SELECT * FROM event_streams; SELECT * FROM event_deliveries',scope:'Every event-table column, receiver bodies, server logs and console responses. Credential input/state, user identities and TLS/master keys remain private fixture inputs. Configured receiver Authorization is checked in memory and never exported.'},null,2));
 console.log(`Plan32 privacy: ${names.length} artifacts, ${bytes} bytes, actual source hash/token and representative passwords/upstream/webhook/Action secrets absent`);
}
if(process.argv[1]===import.meta.filename){await ({setup,sdk,resume,audit}[process.argv[2]]??(()=>{throw Error('unknown SDK fixture mode')}))();}
