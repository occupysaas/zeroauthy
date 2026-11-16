import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {api,manager,code,localClaims,fixtureFetch,exchangeGrant,appleType,persistPublic,noAppleSecret,work} from './m39a-apple-client.mjs';
const m=await manager();
if(process.argv[2]==='setup'){
 const key=await readFile(process.env.E2E_APPLE_KEY,'utf8');
 const body={name:'apple',strategy:'apple',enabled_clients:['m24-spa','apple-native','apple-confidential','apple-disabled'],options:{client_id:'test.apple.web',team_id:'ABCDE12345',kid:'ABCDE67890',app_secret:key,name:true,email:true}};
 const c=await m.connections.create(body);assert.equal(c.strategy,'apple');await noAppleSecret(c);
 const got=await m.connections.get(c.id);await noAppleSecret(got);assert.equal(got.options.client_id,'test.apple.web');
 const patched=await m.connections.update(c.id,{options:{...got.options,set_user_root_attributes:'on_each_login'}});await noAppleSecret(patched);
 assert.ok((await m.connections.list({strategy:['apple']})).data.some(x=>x.id===c.id));
 const temporary=await m.connections.create({...body,name:'apple-temporary',enabled_clients:[]});await m.connections.delete(temporary.id);await assert.rejects(m.connections.get(temporary.id),e=>e.statusCode===404);
 await persistPublic('sdk-connection',await m.connections.get(c.id));
 console.log('Apple node-auth0 7.4.0: create/list/get/update/delete and write-only signing key passed');
 process.exit(0);
}
async function exchange(subject,{client='apple-native',secret,profile,subjectCode}={}){
 const r=await fixtureFetch('https://sdk.e2e.test/oauth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:exchangeGrant,subject_token_type:appleType,subject_token:subjectCode??await code(subject),client_id:client,...(secret?{client_secret:secret}:{}),scope:'openid profile email',...(profile?{user_profile:profile}:{})})});return {status:r.status,body:await r.json()};
}
for(const [subject,opts] of [['native-public',{profile:{name:{firstName:'Native',lastName:'First'},email:'untrusted@example.test'}}],['native-confidential',{client:'apple-confidential',secret:'apple-confidential-fixture-secret'}]]){
 const r=await exchange(subject,opts);assert.equal(r.status,200,`native ${subject} status`);const c=await localClaims(r.body.id_token,opts.client??'apple-native');assert.equal(c.sub,`apple|${subject}`);assert.ok(r.body.access_token);
}
const repeat=await exchange('native-public',{profile:{name:{firstName:'Changed',lastName:'Later'}}});assert.equal(repeat.status,200);assert.equal((await m.users.get('apple|native-public')).name,'Native First');
for(const [subject,opts,status,error] of [
 ['wrong-audience',{},400,'invalid_grant'],
 ['disabled-user',{client:'apple-disabled'},400,'invalid_request'],
 ['confidential-missing-secret',{client:'apple-confidential'},401,'invalid_client'],
 ['invalid-code',{subjectCode:'apple-invalid-runtime-code-sensitive'},400,'invalid_grant'],
]){
 const r=await exchange(subject,opts);assert.equal(r.status,status,`${subject} status`);assert.equal(r.body.error,error);await assert.rejects(m.users.get(`apple|${subject}`),e=>e.statusCode===404);
}
// Reserved Apple type is rejected before action lookup; it cannot be installed
// as a custom profile or claimed by a client's custom-profile permission.
const reserved=await api('token-exchange-profiles','POST',{name:'Apple type isolation',subject_token_type:appleType,action_id:'act_does_not_exist',type:'custom_authentication'});assert.equal(reserved.status,400);assert.match(reserved.body.message,/subject_token_type|reserved/i);
const cliEnv={...process.env,HOME:`${work}/cli-home`,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
const outputs=[];
for(const args of [['connections','list','--json'],['connections','show',(await m.connections.list({strategy:['apple']})).data[0].id,'--json']]){
 const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env:cliEnv,encoding:'utf8',timeout:60000});assert.equal(r.status,0,`${args[1]} CLI status`);assert.ok(!r.error);const out=JSON.parse(r.stdout);await noAppleSecret(out);outputs.push({stdout:out,stderr:r.stderr});
 if(args[1]==='list')assert.ok(out.some(c=>c.strategy==='apple'));else assert.equal(out.strategy,'apple');
}
await persistPublic('cli-output',outputs);
console.log('Apple native: public/confidential verified tokens, first name, wrong bundle no user, disabled flag, client authentication, upstream error, reserved-profile isolation and Auth0 CLI 1.37.0 list/show passed');
