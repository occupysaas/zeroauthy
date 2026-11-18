import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {Agent,setGlobalDispatcher} from 'undici';
import {ManagementClient} from 'auth0';
import {api,token,fixtureDispatcher,primary,upstream} from './social/client.mjs';
setGlobalDispatcher(fixtureDispatcher);
const work=process.env.E2E_M36_WORK;
const client=new ManagementClient({domain:primary,token:await token(),maxRetries:0});
const discovery='https://idp.e2e.test/enterprise/.well-known/openid-configuration';
async function register(value){const r=await fetch('http://127.0.0.1:9173/enterprise/register',{dispatcher:new Agent(),method:'POST',body:JSON.stringify(value)});assert.equal(r.status,204);}
const mode=process.argv[2]??'setup';
if(mode==='setup'){
 const front=await client.connections.create({name:'enterprise-front',strategy:'oidc',enabled_clients:['m24-spa'],options:{client_id:'front-client',scope:'openid profile email',discovery_url:discovery}});
 assert.equal(front.options.type,'front_channel');assert.equal(front.options.client_secret,undefined);
 await register({ClientID:'front-client'});
 const back=await client.connections.create({name:'enterprise-private',strategy:'oidc',enabled_clients:['m24-spa'],options:{type:'back_channel',client_id:'private-client',scope:'openid profile email',discovery_url:discovery,token_endpoint_auth_method:'private_key_jwt',domain_aliases:['corp.example'],attribute_map:{mapping_mode:'use_map',userinfo_scope:'openid profile groups',attributes:{name:'Mapped ${context.tokenset.name}',email:'${context.tokenset.email}',email_verified:'${context.tokenset.email_verified}',federated_groups:'${context.userinfo.groups}'}}}});
 await assert.rejects(client.connections.update(back.id,{options:{...back.options,attribute_map:{mapping_mode:'use_map',attributes:{name:'${context.tokenset.access_token}'}}}}),e=>e.statusCode===400);
 const malformed=await api(`connections/${back.id}`,'PATCH',{options:{...back.options,scope:['openid'],scopes:['openid']}});assert.equal(malformed.status,400);
 assert.deepEqual(await client.connections.keys.get(back.id),[]);
 const signing=await client.connections.keys.create(back.id,{key_use:'signing',signing_alg:'RS256'});
 assert.equal(signing.length,2);assert.ok(signing.every(k=>!k.cert.includes('PRIVATE KEY')));
 await assert.rejects(client.connections.keys.create(back.id,{}),e=>e.statusCode===409);
 const current=await client.connections.keys.rotate(back.id,{});assert.equal(current.current,true);
 const encryption=await client.connections.keys.create(back.id,{key_use:'encryption',encryption_alg:'RSA-OAEP-256'});
 const enc=encryption.find(k=>k.key_use==='encryption'&&k.current);assert.ok(enc);
 await client.connections.update(back.id,{options:{...back.options,id_token_encrypted_response_alg:'RSA-OAEP-256',id_token_encrypted_response_encs:['A256GCM'],enable_pushed_authorization_requests:true}});
 await register({ClientID:'private-client',SigningCert:current.cert,EncryptionCert:enc.cert,EncryptionAlg:'RSA-OAEP-256',PAR:true});
 const okta=await client.connections.create({name:'enterprise-okta',strategy:'okta',enabled_clients:['m24-spa'],options:{domain:'idp.e2e.test',client_id:'okta-client',client_secret:upstream.secret,scope:'openid profile email',issuer:'https://idp.e2e.test/enterprise',authorization_endpoint:'https://idp.e2e.test/enterprise/authorize',token_endpoint:'https://idp.e2e.test/enterprise/token',jwks_uri:'https://idp.e2e.test/enterprise/jwks',connection_settings:{pkce:'S256'}}});
 await register({ClientID:'okta-client'});
 await assert.rejects(client.connections.checkStatus(back.id),e=>e.statusCode===404);
 const all=await api('connections');const db=all.body.find(c=>c.strategy==='auth0');assert.ok(db);
 const user=await client.users.create({connection:db.name,email:'delete-enterprise@example.test',password:'Throwaway-Enterprise-Password-2026!'});
 await client.connections.users.deleteByEmail(db.id,{email:'delete-enterprise@example.test'});await assert.rejects(client.users.get(user.user_id),e=>e.statusCode===404);
 assert.equal((await api('prompts','PATCH',{identifier_first:true})).status,200);
 await writeFile(`${work}/connections.json`,JSON.stringify({front:front.id,back:back.id,okta:okta.id}),{mode:0o600});
 console.log('Plan 36 SDK: OIDC/Okta create, public keys create/rotate, status and delete-by-email passed');
}else{
 const ids=JSON.parse(await readFile(`${work}/connections.json`,'utf8'));
 const reader=new ManagementClient({domain:primary,token:await token(undefined,'read:users'),maxRetries:0});
 for(const [name,id]of [['front',ids.front],['private',ids.back],['okta',ids.okta]]){const c=await client.connections.get(id);assert.equal(c.options.client_secret,undefined);const sub=`${name}-user`;const identity=name==='okta'?`okta|enterprise-okta|${sub}`:`oidc|enterprise-${name}|${sub}`;const user=await reader.users.get(identity);assert.equal(user.identities[0].isSocial,false);assert.equal(user.identities[0].access_token,undefined);if(name==='private'){assert.equal(user.name,'Mapped Workforce private-user');assert.deepEqual(user.identities[0].profileData.federated_groups,['engineering','staff']);}if(name==='front'){const privileged=new ManagementClient({domain:primary,token:await token(undefined,'read:users read:user_idp_tokens'),maxRetries:0});assert.equal((await privileged.users.get(identity)).identities[0].access_token,undefined)}}
 await writeFile(`${work}/public-users.json`,JSON.stringify((await api('users')).body),{mode:0o600});
 console.log('Plan 36 SDK: front-channel, signed-client assertion/PAR/JWE/userinfo mapping and Okta profiles verified');
}
