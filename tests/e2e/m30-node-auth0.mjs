import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {Agent,setGlobalDispatcher} from 'undici';
import {ManagementClient} from 'auth0';
import {api,token,primary,fixtureDispatcher} from './organizations/client.mjs';
setGlobalDispatcher(fixtureDispatcher);
assert.equal(JSON.parse(await readFile(new URL('./node_modules/auth0/package.json',import.meta.url),'utf8')).version,'7.4.0');
const m=new ManagementClient({domain:primary,token:await token(),maxRetries:0}),o=m.organizations;
const connection=(await m.connections.list()).data.find(x=>x.name==='Username-Password-Authentication');
await m.clients.update('m24-spa',{initiate_login_uri:'https://callback.e2e.test/invitation-login'});
const org=await o.create({name:'plan30-invitations',display_name:'Plan30 Invitations'});
await o.enabledConnections.add(org.id,{connection_id:connection.id,assign_membership_on_login:true,is_signup_enabled:true});
const {deploy,bind}=await import('./m27-node-auth0.mjs');
const mail=await deploy(m,'Plan30 mail capture',`exports.onExecuteCustomEmailProvider=async(e)=>{await fetch('http://127.0.0.1:9173/m28/sink',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'mail',notification:e.notification,organization:e.organization})})}`,'custom-email-provider');
await bind(m,[mail],'custom-email-provider');
assert.equal((await api('emails/provider','POST',{name:'custom',enabled:true,default_from_address:'fixture@example.test'})).status,201);
const claim=await deploy(m,'Plan30 organization claim',`exports.onExecutePostLogin=(e,a)=>{if(e.organization)a.idToken.setCustomClaim('https://plan30.test/org',e.organization.id)}`);
await bind(m,[claim]);
const invitation=await o.invitations.create(org.id,{inviter:{name:'Plan30 operator'},invitee:{email:'plan30-new@e2e.local'},client_id:'m24-spa',connection_id:connection.id,send_invitation_email:true});
assert.ok(invitation.invitation_url.startsWith('https://callback.e2e.test/invitation-login?'));
assert.equal((await o.invitations.get(org.id,invitation.id)).invitee.email,'plan30-new@e2e.local');
assert.ok((await o.invitations.list(org.id)).data.some(x=>x.id===invitation.id));
await writeFile(process.env.E2E_M29_STATE,JSON.stringify({org:org.id,connection:connection.id,invitation}),{mode:0o600});
// Delivery travels through the durable worker and actual custom-provider Action.
const delivered=await fetch('http://127.0.0.1:9173/m28/sink',{dispatcher:new Agent()});
assert.equal(delivered.status,200,'invitation mail capture is required');
console.log('Plan30 SDK invitation creation, get, list and application URL passed');

const disposable=await o.invitations.create(org.id,{inviter:{name:'SDK'},invitee:{email:'delete30@e2e.local'},client_id:'m24-spa',send_invitation_email:false});
await o.invitations.delete(org.id,disposable.id);await assert.rejects(o.invitations.get(org.id,disposable.id),e=>e.statusCode===404);
await o.clients.create(org.id,{clients:[{client_id:'m24-spa',use_for_member_access:true}]});
assert.equal((await o.clients.get(org.id,'m24-spa')).use_for_member_access,true);
await o.clients.update(org.id,'m24-spa',{use_for_member_access:false});assert.equal((await o.clients.get(org.id,'m24-spa')).use_for_member_access,false);
await o.clients.delete(org.id,{clients:['m24-spa']});
const domain=await o.discoveryDomains.create(org.id,{domain:'plan30.e2e.local'});
assert.equal((await o.discoveryDomains.getByName(org.id,'PLAN30.e2e.local')).id,domain.id);
assert.equal((await o.discoveryDomains.get(org.id,domain.id)).status,'pending');
await o.discoveryDomains.update(org.id,domain.id,{status:'verified'});
assert.equal((await o.discoveryDomains.list(org.id)).data[0].status,'verified');
await o.discoveryDomains.delete(org.id,domain.id);
await o.create({name:'plan30-second'});
const search=await api('organizations/search?take=1&sort=name');assert.equal(search.status,200);assert.ok(search.body.next);
assert.equal((await api('organizations/search?take=1&sort=display_name&from='+encodeURIComponent(search.body.next))).status,400);
assert.equal((await api('organizations/search?take=1&sort=name&from='+encodeURIComponent(search.body.next+'x'))).status,400);
assert.ok((await o.search({q:'name:plan30*',take:100})).data.some(x=>x.id===org.id));
console.log('Plan30 SDK: invitation CRUD; application association CRUD; discovery domain CRUD/attestation; search and cursor rejection passed');
const audience='https://plan30-api.e2e.test';
await m.resourceServers.create({name:'Plan30 API',identifier:audience,scopes:[{value:'read:data'}],subject_type_authorization:{client:{policy:'require_client_grant'},user:{policy:'allow_all'}}});
const machines={};for(const first of [true,false]){const machine=await m.clients.create({name:'Plan30 machine',app_type:'non_interactive',client_secret:'Plan30-machine-secret-for-local-fixture-not-for-production-2026',token_endpoint_auth_method:'client_secret_post',grant_types:['client_credentials'],is_first_party:first});
const grant=await m.clientGrants.create({client_id:machine.client_id,audience,scope:['read:data']});
machines[first]={machine,grant};}
let cells=0;
for(const first of [true,false])for(const third of ['block','allow'])for(const usage of ['deny','allow','require'])for(const any of [false,true])for(const associated of [false,true]){
 const {machine,grant}=machines[first];await o.update(org.id,{third_party_client_access:third});
 if(!first&&any){await assert.rejects(m.clientGrants.update(grant.id,{organization_usage:usage,allow_any_organization:any}),e=>e.statusCode===400);cells++;continue;}
 await m.clientGrants.update(grant.id,{organization_usage:usage,allow_any_organization:any});
 if(third==='block'&&!any&&!associated){
 const r=await (await import('./social/client.mjs')).fixtureFetch(`https://${primary}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:machine.client_id,client_secret:'Plan30-machine-secret-for-local-fixture-not-for-production-2026',audience})});
 const b=await r.json();assert.equal(r.status,usage==='require'?403:200,`omitted organization first=${first} usage=${usage}`);if(usage==='require')assert.equal(b.access_token,undefined);else assert.equal(JSON.parse(Buffer.from(b.access_token.split('.')[1],'base64url')).org_id,undefined);
 }
 if(associated)await o.clientGrants.create(org.id,{grant_id:grant.id});
 const response=await (await import('./social/client.mjs')).fixtureFetch(`https://${primary}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:machine.client_id,client_secret:'Plan30-machine-secret-for-local-fixture-not-for-production-2026',audience,organization:org.id})});
 const body=await response.json();const allowed=usage!=='deny'&&(first?(any||associated):(!any&&associated&&third==='allow'));
 assert.equal(response.status,allowed?200:403,`M2M cell first=${first} third=${third} usage=${usage} any=${any} associated=${associated}`);
 if(allowed)assert.equal(JSON.parse(Buffer.from(body.access_token.split('.')[1],'base64url')).org_id,org.id);else assert.equal(body.access_token,undefined);
 if(associated)await o.clientGrants.delete(org.id,grant.id);cells++;
}
await o.update(org.id,{third_party_client_access:'block'});
console.log(`Plan30 real token endpoint: ${cells} first/third-party M2M policy configurations and six omitted-organization token requests passed (third-party allow-any rejected at management)`);
