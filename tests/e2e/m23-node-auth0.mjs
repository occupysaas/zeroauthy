// Real pinned node-auth0 7.4.0, including all nine custom-domain operations.
import assert from 'node:assert/strict';
import https from 'node:https';
import { ManagementClient } from 'auth0';
import { setGlobalDispatcher } from 'undici';
import { api, token, publish, noSecret, primary, replicaDispatcher, fixtureDispatcher } from './domains/client.mjs';
// This standalone SDK process owns its dispatcher; imported browser helpers do not.
setGlobalDispatcher(fixtureDispatcher);
const make=async(domain=primary,scope)=>new ManagementClient({domain,token:await token(domain,scope),maxRetries:0});
const m=await make(); const other=await make('cli.e2e.test');
const name='sdk.domains.e2e.test';
assert.equal((await m.customDomains.getDefault()).domain,primary);
const d=await m.customDomains.create({domain:name.toUpperCase()+'.',type:'self_managed_certs',custom_client_ip_header:'cf-connecting-ip',domain_metadata:{team:'SDK'}});
const id=d.custom_domain_id;
assert.ok(id); assert.equal(d.domain,name); assert.equal(d.status,'pending_verification'); noSecret(d);
await assert.rejects(m.customDomains.setDefault({domain:name}),e=>e.statusCode===409);
assert.equal((await m.customDomains.get(id)).domain,name);
await assert.rejects(other.customDomains.get(id),e=>e.statusCode===404);
await assert.rejects(other.customDomains.create({domain:name,type:'self_managed_certs'}),e=>e.statusCode===409);
await publish(d);
// The other independently opened SQL handle must observe the pending row and
// commit proof; no fixture writes a ready domain or plaintext proxy key.
// Request SDK calls through node one; raw node-two observation below uses a
// second CONNECT proxy forwarding to node two and preserves public origin.
const secondPending=await fetch(`https://${primary}/api/v2/custom-domains/${id}`,{dispatcher:replicaDispatcher,headers:{authorization:`Bearer ${await token()}`}});
assert.equal(secondPending.status,200);assert.equal((await secondPending.json()).status,'pending_verification');
const v=await m.customDomains.verify(id); assert.equal(v.status,'ready'); assert.ok(v.cname_api_key);
const key=v.cname_api_key;
const secondReady=await fetch(`https://${primary}/api/v2/custom-domains/${id}`,{dispatcher:replicaDispatcher,headers:{authorization:`Bearer ${await token()}`}});
assert.equal(secondReady.status,200);assert.equal((await secondReady.json()).status,'ready');
noSecret(await m.customDomains.get(id)); noSecret(await m.customDomains.list()); noSecret(await m.customDomains.verify(id));
assert.equal((await m.customDomains.setDefault({domain:name})).domain,name);
assert.equal((await m.customDomains.getDefault()).domain,name);
assert.equal((await m.customDomains.update(id,{domain_metadata:{team:'updated'},relying_party_identifier:'e2e.test'})).domain_metadata.team,'updated');
const projected=await m.customDomains.list({q:`domain:"${name}"`,fields:'domain',include_fields:true});
assert.deepEqual(projected,[{domain:name}]);
await assert.rejects(m.customDomains.list({q:'x'.repeat(1025)}),e=>e.statusCode===400);
await assert.rejects(m.customDomains.update(id,{tls_policy:'compatible'}),e=>e.statusCode===400);
await assert.rejects(m.customDomains.create({domain:'127.0.0.1',type:'self_managed_certs'}),e=>e.statusCode===400);
const reader=await make(primary,'read:custom_domains');
assert.ok(await reader.customDomains.list());
for(const write of [()=>reader.customDomains.create({domain:'denied.domains.e2e.test',type:'self_managed_certs'}),()=>reader.customDomains.update(id,{}),()=>reader.customDomains.verify(id),()=>reader.customDomains.test(id),()=>reader.customDomains.setDefault({domain:primary}),()=>reader.customDomains.delete(id)]) await assert.rejects(write,e=>e.statusCode===403);
// Real TLS with matching public SNI/Host and trusted proxy peer. A forged key,
// absent configured IP, and spoofed forwarded host cannot switch tenants.
for(const headers of [{},{'cname-api-key':'wrong','cf-connecting-ip':'1.1.1.1'},{'cname-api-key':key}]) {
 const r=await fetch(`https://${name}/.well-known/openid-configuration`,{headers}); assert.ok([400,403].includes(r.status),String(r.status));
}

async function direct({host=name,sni=name,peer='127.0.0.1'}={}) {
 return new Promise((resolve,reject)=>{
  const req=https.request({hostname:'127.0.0.1',port:9443,servername:sni,localAddress:peer,path:'/.well-known/openid-configuration',headers:{host,'cname-api-key':key,'cf-connecting-ip':'1.1.1.1'}},r=>{r.resume();r.on('end',()=>resolve(r.statusCode))});req.on('error',reject);req.end();
 });
}
assert.equal(await direct({peer:'127.0.0.2'}),403);
assert.equal(await direct({host:d.origin_domain_name}),421);
const headers={'cname-api-key':key,'cf-connecting-ip':'1.1.1.1','x-forwarded-host':'cli.e2e.test','x-forwarded-for':'10.0.0.1'};
const doc=await fetch(`https://${name}/.well-known/openid-configuration`,{headers}).then(r=>r.json());
const replicaDoc=await fetch(`https://${name}/.well-known/openid-configuration`,{dispatcher:replicaDispatcher,headers}).then(r=>r.json());assert.equal(replicaDoc.issuer,`https://${name}/`);
assert.equal(doc.issuer,`https://${name}/`); assert.equal(doc.token_endpoint,`https://${name}/oauth/token`);
await assert.rejects(m.customDomains.test(id),e=>e.statusCode===429);
// Preserve the actual distributed 30s admission limit rather than injecting
// a fast clock into the SQL store.
await new Promise(r=>setTimeout(r,30_100));
const diagnostic=await m.customDomains.test(id); assert.equal(diagnostic.success,false);
assert.match(diagnostic.message,/403/); // the diagnostic cannot impersonate a proxy
await m.customDomains.setDefault({domain:primary}); await m.customDomains.delete(id);
await assert.rejects(m.customDomains.get(id),e=>e.statusCode===404);
assert.equal((await fetch(`https://${name}/.well-known/openid-configuration`,{headers})).status,404);
console.log('m23-node-auth0: nine real SDK operations; DNS proof, scopes, claims, defaults, query, one-time keys, proxy admission and deletion passed');
