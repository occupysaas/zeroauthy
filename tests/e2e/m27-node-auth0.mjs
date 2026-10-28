import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {ManagementClient} from 'auth0';
import {token,primary,api,fixtureFetch} from './social/client.mjs';
import {audience,email,password,key,grant,decode} from './rbac/client.mjs';
export const management=async()=>new ManagementClient({domain:primary,token:await token(),maxRetries:0});
export async function built(m,id){for(let n=0;n<300;n++){const a=await m.actions.get(id);if(a.status==='built')return a;assert.notEqual(a.status,'failed',JSON.stringify(a.errors));await new Promise(r=>setTimeout(r,100));}throw Error('Action build did not finish');}
export async function deploy(m,name,code,trigger='post-login',extra={}){const a=await m.actions.create({name,code,runtime:'node22',supported_triggers:[{id:trigger,version:trigger==='post-login'?'v3':'v2'}],...extra});await built(m,a.id);await m.actions.deploy(a.id);return a;}
export async function bind(m,as,trigger='post-login'){return m.actions.triggers.bindings.updateMany(trigger,{bindings:as.map(a=>({ref:{type:'action_id',value:a.id},display_name:a.name}))});}

if(process.argv[1]===import.meta.filename){
 const m=await management();
 const resource=await m.resourceServers.create({name:'Plan27 API',identifier:audience,enforce_policies:true,token_dialect:'access_token_authz',skip_consent_for_verifiable_first_party_clients:true,scopes:[{value:'read:x'},{value:'write:x'}]});
 const user=await m.users.create({connection:'Username-Password-Authentication',email,password,email_verified:true});
 const role=await m.roles.create({name:'Plan27 default role'});await m.roles.permissions.add(role.id,{permissions:[key('read:x')]});
 // Seven Action endpoints, three version endpoints, two binding endpoints,
 // triggers discovery and execution get: all fourteen via the pinned SDK.
 assert.ok((await m.actions.triggers.list()).triggers.some(t=>t.id==='post-login'));
 const a=await deploy(m,'SDK Claim',`exports.onExecutePostLogin=async(e,a)=>{a.idToken.setCustomClaim('https://actions.test/id','sdk');a.accessToken.setCustomClaim('https://actions.test/access','sdk');a.idToken.setCustomClaim('https://actions.test/roles',e.authorization.roles);};`);
 assert.ok((await m.actions.list()).data.some(x=>x.id===a.id));
 assert.equal((await m.actions.get(a.id)).name,a.name);
 await m.actions.update(a.id,{name:'SDK Claim updated'});await built(m,a.id);
 const version=await m.actions.deploy(a.id);
 assert.ok((await m.actions.versions.list(a.id)).data.length>=2);
 assert.equal((await m.actions.versions.get(a.id,version.id)).id,version.id);
 await m.actions.versions.deploy(a.id,version.id,{});
 const tested=await m.actions.test(a.id,{payload:{authorization:{roles:[]}}});
 assert.ok(tested.payload.commands.length>=2);
 await assert.rejects(m.actions.executions.get(tested.payload.execution_id),e=>e.statusCode===404); // Dry runs intentionally persist nothing.
 await bind(m,[a]);assert.equal((await m.actions.triggers.bindings.list('post-login')).data[0].action.id,a.id);
 const initial=await grant();assert.deepEqual(decode(initial.access_token).permissions,[]);assert.equal(decode(initial.id_token)['https://actions.test/id'],'sdk');
 await bind(m,[]);await m.actions.delete(a.id);await assert.rejects(m.actions.get(a.id),e=>e.statusCode===404);
 const claims=await deploy(m,'Browser Claims',`exports.onExecutePostLogin=async(e,a)=>{a.idToken.setCustomClaim('https://actions.test/id','browser');a.accessToken.setCustomClaim('https://actions.test/access','browser');a.idToken.setCustomClaim('https://actions.test/roles',e.authorization.roles);};`);
 const deny=await deploy(m,'Browser Deny',`exports.onExecutePostLogin=async(e,a)=>a.access.deny('Plan27 blocked by Action');`);
 const redirect=await deploy(m,'Browser Redirect',`exports.onExecutePostLogin=async(e,a)=>{const t=a.redirect.encodeToken({secret:e.secrets.KEY,payload:{fixture:true}});a.redirect.sendUserTo('https://callback.e2e.test/redirect',{query:{session_token:t}});};exports.onContinuePostLogin=async(e,a)=>{const t=a.redirect.validateToken({secret:e.secrets.KEY});if(!t.fixture||e.request.query.a!=='1')return a.access.deny('bad redirect');a.idToken.setCustomClaim('https://actions.test/redirect',true);};`,'post-login',{secrets:[{name:'KEY',value:'m27-redirect-token-secret'}]});
 const defaultRole=await deploy(m,'Assign default role',`exports.onExecutePostLogin=async(e,a)=>{const {ManagementClient}=require('auth0');const m=new ManagementClient({domain:'sdk.e2e.test',clientId:e.secrets.CLIENT_ID,clientSecret:e.secrets.CLIENT_SECRET,maxRetries:0,fetch:(url,init)=>fetch('http://127.0.0.1:9173/action-sdk'+new URL(url).pathname,init)});await m.users.roles.assign(e.user.user_id,{roles:[e.secrets.ROLE]});};`,'post-login',{dependencies:[{name:'auth0',version:'7.4.0'}],secrets:[{name:'CLIENT_ID',value:'m24-admin'},{name:'CLIENT_SECRET',value:'m24-admin-secret-not-for-production'},{name:'ROLE',value:role.id}]});
 await bind(m,[defaultRole]);
 const first=await grant();assert.deepEqual(decode(first.access_token).permissions,[]);
 await bind(m,[claims]);
 const next=await grant();assert.deepEqual(decode(next.access_token).permissions,['read:x']);assert.deepEqual(decode(next.id_token)['https://actions.test/roles'],[role.name]);
 const cc=await deploy(m,'Credentials Claims',`exports.onExecuteCredentialsExchange=async(e,a)=>a.accessToken.setCustomClaim('https://actions.test/m2m','yes');`,'credentials-exchange');
 const ccDeny=await deploy(m,'Credentials Deny',`exports.onExecuteCredentialsExchange=async(e,a)=>a.access.deny('invalid_request','Plan27 credentials denied');`,'credentials-exchange');
 await m.clientGrants.create({client_id:'m26-password',audience,scope:['read:x']});
 await m.clients.update('m26-password',{grant_types:['password','client_credentials','refresh_token']});
 async function credentials(){return fixtureFetch(`https://${primary}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:'m26-password',client_secret:'m26-password-secret-not-for-production',audience})});}
 await bind(m,[cc],'credentials-exchange');let r=await credentials();assert.equal(r.status,200);assert.equal(decode((await r.json()).access_token)['https://actions.test/m2m'],'yes');
 await bind(m,[ccDeny],'credentials-exchange');r=await credentials();assert.equal(r.status,400);const denied=await r.json();assert.equal(denied.error,'invalid_request');assert.equal(denied.error_description,'Plan27 credentials denied');assert.equal(denied.access_token,undefined);
 await bind(m,[],'credentials-exchange');
 await writeFile(process.env.E2E_M27_STATE,JSON.stringify({claims,deny,redirect,defaultRole,role,user,resource}),{mode:0o600});
 console.log('Plan27 node-auth0 7.4.0: all 14 Actions operations; claims/roles; real registry-built ManagementClient default role on next login; credentials claims and deny passed');
}
