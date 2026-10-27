import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { ManagementClient } from 'auth0';
import { Agent, setGlobalDispatcher } from 'undici';
import { api, token, primary, fixtureDispatcher, READER } from './social/client.mjs';
import { emailConnections, personas, upstreamSecret } from './social/email-accounts.mjs';
setGlobalDispatcher(fixtureDispatcher);
const m=new ManagementClient({domain:primary,token:await token(),maxRetries:0});
function redacted(v){const s=JSON.stringify(v);assert.ok(!s.includes(upstreamSecret)&&!s.includes('client_secret')&&!s.includes('********'));}
if((process.argv[2]??'setup')==='setup') {
 for(const c of emailConnections){const created=await m.connections.create({...c,enabled_clients:['m24-spa'],options:{...c.options,client_secret:upstreamSecret}});redacted(created);redacted(await m.connections.get(created.id));}
 for(const strategy of ['waad','windowslive','google-oauth2']) {const list=(await m.connections.list({strategy:[strategy]})).data;assert.ok(list.length);assert.ok(list.every(c=>c.strategy===strategy));redacted(list);}
 const disposable=await m.connections.create({name:'m25-disposable',strategy:'windowslive',options:{...emailConnections[0].options,client_secret:upstreamSecret}});
 await m.connections.clients.update(disposable.id,[{client_id:'m24-spa',status:true}]);assert.equal((await m.connections.clients.get(disposable.id)).data[0].client_id,'m24-spa');
 await m.connections.clients.update(disposable.id,[{client_id:'m24-spa',status:false}]);await m.connections.delete(disposable.id);await assert.rejects(m.connections.get(disposable.id),e=>e.statusCode===404);
 const d=await m.customDomains.create({domain:'email.custom.e2e.test',type:'self_managed_certs',custom_client_ip_header:'cf-connecting-ip'});
 const txt=d.verification.methods.find(x=>x.name==='txt');const dns=await fetch('http://127.0.0.1:9173/dns',{dispatcher:new Agent(),method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:txt.domain,value:txt.record})});assert.equal(dns.status,204);
 const verified=await m.customDomains.verify(d.custom_domain_id);assert.equal(verified.status,'ready');
 await writeFile(process.env.E2E_M25_DOMAIN_FILE,JSON.stringify({key:verified.cname_api_key}),{mode:0o600});
 console.log('m25 SDK setup: four connections, filtering, CRUD, client enablement, DNS-proven custom domain');
} else {
 const users=(await m.users.list({q:'identities.provider:"waad" OR identities.provider:"windowslive" OR identities.provider:"google-oauth2"',search_engine:'v3'})).data;
 assert.deepEqual(users.map(u=>u.user_id).sort(),personas.map(p=>p[3]).sort());
 for(const [connection,,,id,email] of personas){const user=await m.users.get(id);assert.equal(user.email,email);assert.equal(user.email_verified,email===undefined?undefined:connection==='google-oauth2');assert.equal(user.identities.length,1);assert.equal(user.identities[0].connection,connection);assert.equal(user.identities[0].isSocial,connection!=='microsoft-directory'&&connection!=='microsoft-organizations');assert.equal(user.identities[0].access_token,undefined);}
 for(const id of ['windowslive|Sub-outlook',personas[0][3],personas[8][3]]){
  const response=await api('users/'+encodeURIComponent(id),'GET',undefined,await token(READER,'read:users read:user_idp_tokens'));assert.equal(response.status,200);assert.equal(typeof response.body.identities[0].access_token,'string');assert.equal(response.headers.get('cache-control'),'no-store');
  const list=await api('users?q='+encodeURIComponent(`user_id:"${id}"`),'GET',undefined,await token(READER,'read:users read:user_idp_tokens'));assert.ok(!JSON.stringify(list.body).includes('access_token'));
 }
 console.log(`m25 SDK verify: ${users.length} distinct identities, repeat ownership, missing email, scoped tokens`);
}
