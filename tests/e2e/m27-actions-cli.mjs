import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync,readFileSync} from 'node:fs';
import {management,built} from './m27-node-auth0.mjs';
const home=mkdtempSync('/tmp/za-m27-cli-');
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
function run(args,status=0){const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60_000});assert.ok(!r.error,String(r.error));assert.equal(r.status,status,`${args.slice(0,3).join(' ')}: ${r.stderr}`);try{return JSON.parse(r.stdout)}catch{return r.stdout}}
try{
 const m=await management();
 const a=run(['actions','create','--name','CLI Action','--trigger','post-login','--runtime','node22','--code',`exports.onExecutePostLogin=async(e,a)=>a.idToken.setCustomClaim('https://actions.test/cli',true);`,'--json']);
 assert.equal(run(['actions','show',a.id,'--json']).name,'CLI Action');
 assert.ok(run(['actions','list','--json']).some(x=>x.id===a.id));
 run(['actions','update',a.id,'--name','CLI updated','--force','--json']);await built(m,a.id);
 run(['actions','deploy',a.id,'--json']);
 run(['api','patch','actions/triggers/post-login/bindings','--data',JSON.stringify({bindings:[{ref:{type:'action_id',value:a.id}}]})]);
 assert.equal(run(['api','get','actions/triggers/post-login/bindings']).bindings[0].action.id,a.id);
 const fixture=JSON.parse(readFileSync(process.env.E2E_M27_STATE,'utf8'));assert.equal(run(['api','get',`actions/executions/${fixture.execution}`]).id,fixture.execution);
 run(['api','get','actions/executions/missing-cli-execution'],1);
 run(['api','patch','actions/triggers/post-login/bindings','--data','{"bindings":[]}']);
 run(['actions','delete',a.id,'--force']);run(['actions','show',a.id,'--json'],1);
 console.log('Plan27 Auth0 CLI 1.37.0: actions create/list/show/update/deploy/delete; API binding read/update and execution missing-resource handling passed');
}finally{rmSync(home,{recursive:true,force:true})}
