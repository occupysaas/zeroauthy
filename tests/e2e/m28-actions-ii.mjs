import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {readFile,writeFile} from 'node:fs/promises';
import {management,built,deploy,bind} from './m27-node-auth0.mjs';
import {api} from './social/client.mjs';
export const triggers={'pre-user-registration':'onExecutePreUserRegistration','post-user-registration':'onExecutePostUserRegistration','post-change-password':'onExecutePostChangePassword','password-reset-post-challenge':'onExecutePostChallenge','custom-email-provider':'onExecuteCustomEmailProvider'};
export async function moduleBuilt(m,id){for(let n=0;n<300;n++){const a=await m.actions.modules.get(id);if(a.status==='built')return a;assert.notEqual(a.status,'failed',JSON.stringify(a.errors));await new Promise(r=>setTimeout(r,100));}throw Error('module build timeout');}
if(process.argv[1]===import.meta.filename){
 assert.equal(JSON.parse(await readFile(new URL('./node_modules/auth0/package.json',import.meta.url),'utf8')).version,'7.4.0');
 const m=await management(),mods=m.actions.modules;
 const a=await mods.create({name:'sdk-util',code:"exports.value=()=> 'sdk-module'"});await moduleBuilt(m,a.id);
 assert.ok((await mods.list()).data.some(x=>x.id===a.id));assert.equal((await mods.get(a.id)).name,'sdk-util');
 const v=await mods.versions.create(a.id);assert.equal((await mods.versions.get(a.id,v.id)).version_number,1);assert.equal((await mods.versions.list(a.id)).data.length,1);
 await mods.update(a.id,{code:"exports.value=()=> 'sdk-module-v2'"});await moduleBuilt(m,a.id);await mods.versions.create(a.id);await mods.rollback(a.id,{module_version_id:v.id});const rolled=await moduleBuilt(m,a.id);assert.equal(rolled.code,"exports.value=()=> 'sdk-module'");assert.equal(rolled.latest_version_number,2);assert.equal((await mods.versions.get(a.id,v.id)).code,"exports.value=()=> 'sdk-module'");
 const consumer=await deploy(m,'SDK module consumer',`exports.onExecutePreUserRegistration=(e,a)=>a.user.setAppMetadata('module',require('actions:sdk-util').value());`,'pre-user-registration',{modules:[{module_id:a.id,module_version_id:v.id}]});
 assert.ok((await mods.listActions(a.id)).data.some(x=>x.action_id===consumer.id));await m.actions.delete(consumer.id);await mods.delete(a.id);await assert.rejects(mods.get(a.id),e=>e.statusCode===404);
 console.log('node-auth0 7.4.0: all ten module operations passed (no raw fallback needed)');
 const home=mkdtempSync('/tmp/za-m28-cli-');
 const env={...process.env,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
 function run(args){const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60000});assert.equal(r.status,0,`${args.slice(0,3).join(' ')}: ${r.stderr}`);try{return JSON.parse(r.stdout)}catch{return r.stdout}}
 try{
  for(const [trigger,handler]of Object.entries(triggers)){const a=run(['actions','create','--name',`CLI ${trigger}`,'--trigger',trigger,'--runtime','node22','--code',`exports.${handler}=()=>{};`,'--json']);await built(m,a.id);run(['actions','deploy',a.id,'--json']);assert.equal((await m.actions.get(a.id)).supported_triggers[0].id,trigger);run(['actions','delete',a.id,'--force']);}
  const raw=(method,route,body)=>run(['api',method,`actions/modules${route}`,...(method==='delete'?['--force']:[]),...(body===undefined?[]:['--data',JSON.stringify(body)])]);
  const mod=raw('post','',{name:'cli-util',code:'exports.value=()=>1'});await moduleBuilt(m,mod.id);assert.ok(raw('get','').modules.some(x=>x.id===mod.id));assert.equal(raw('get',`/${mod.id}`).name,'cli-util');const ver=raw('post',`/${mod.id}/versions`);assert.equal(raw('get',`/${mod.id}/versions/${ver.id}`).id,ver.id);assert.equal(raw('get',`/${mod.id}/versions`).versions.length,1);assert.equal(raw('get',`/${mod.id}/actions`).actions.length,0);raw('patch',`/${mod.id}`,{code:'exports.value=()=>2'});await moduleBuilt(m,mod.id);raw('post',`/${mod.id}/rollback`,{module_version_id:ver.id});assert.equal((await moduleBuilt(m,mod.id)).code,'exports.value=()=>1');raw('delete',`/${mod.id}`);
 }finally{rmSync(home,{recursive:true,force:true})}
 console.log('Auth0 CLI 1.37.0: create/deploy all five new triggers and all ten raw module operations passed');
 const deny=await deploy(m,'Signup denied',`exports.onExecutePreUserRegistration=(e,a)=>a.access.deny('policy','Plan28 use a work email');`,'pre-user-registration');
 const metadata=await deploy(m,'Signup metadata',`exports.onExecutePreUserRegistration=(e,a)=>{a.user.setAppMetadata('plan','pro');a.user.setUserMetadata('color','blue')};`,'pre-user-registration');
 const registered=await deploy(m,'Registration sink',`exports.onExecutePostUserRegistration=async(e)=>{await fetch('http://127.0.0.1:9173/m28/sink',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'registered',user:e.user})})};`,'post-user-registration');
 const reset=await deploy(m,'Reset round trip',`exports.onExecutePostChallenge=(e,a)=>a.redirect.sendUserTo('https://callback.e2e.test/reset-redirect');exports.onContinuePostChallenge=(e,a)=>{if(e.request.query.ok!=='1')return a.access.deny('missing round trip');a.transaction.setResultUrl('https://callback.e2e.test/reset-done',{query:{result:'plan28'}})};`,'password-reset-post-challenge');
 const mail=await deploy(m,'Custom delivery',`exports.onExecuteCustomEmailProvider=async(e,a)=>{const r=await fetch('http://127.0.0.1:9173/m28/sink',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'mail',notification:e.notification})});const rows=await r.json();if(rows.filter(x=>x.kind==='mail'&&x.notification.to===e.notification.to).length===1)a.notification.retry('Plan28 transient')};`,'custom-email-provider');
 const changed=await deploy(m,'Password changed sink',`exports.onExecutePostChangePassword=async(e)=>{await fetch('http://127.0.0.1:9173/m28/sink',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({kind:'changed',user:e.user})})};`,'post-change-password');
 await bind(m,[registered],'post-user-registration');await bind(m,[reset],'password-reset-post-challenge');await bind(m,[mail],'custom-email-provider');await bind(m,[changed],'post-change-password');
 const provider=await api('emails/provider','POST',{name:'custom',enabled:true,default_from_address:'fixture@example.test'});assert.equal(provider.status,201,JSON.stringify(provider.body));
 await writeFile(process.env.E2E_M28_STATE,JSON.stringify({deny,metadata,registered,reset,mail,changed}),{mode:0o600});
}
