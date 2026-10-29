import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {state} from './organizations/client.mjs';
const home=mkdtempSync('/tmp/za-m29-cli-');
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
function run(args,status=0){const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60_000});assert.ok(!r.error,`${r.error}`);assert.equal(r.status,status,`${args.slice(0,3).join(' ')}: ${r.stderr}`);try{return JSON.parse(r.stdout)}catch{return r.stdout}}
try{
 assert.match(run(['--version']),/1\.37\.0/);
 const f=await state(),org=run(['orgs','create','--name','cli-org','--display','CLI Organization','--json']);
 assert.equal(run(['orgs','show',org.id,'--json']).name,'cli-org');
 assert.ok(run(['orgs','list','--json']).some(x=>x.id===org.id));
 run(['orgs','update',org.id,'--display','CLI Updated','--json']);
 assert.equal(run(['orgs','show',org.id,'--json']).display_name,'CLI Updated');
 assert.ok(run(['orgs','members','list',f.alpha,'--json']).some(x=>x.user_id===f.user));
 assert.ok(run(['orgs','roles','list',f.alpha,'--json']).some(x=>x.id===f.role));
 assert.ok(run(['orgs','roles','members','list',f.alpha,'--role-id',f.role,'--json']).some(x=>x.user_id===f.user));
 run(['orgs','delete',org.id,'--force']);run(['orgs','show',org.id,'--json'],1);
 console.log('Plan29 auth0-cli 1.37.0: orgs create/list/show/update/delete, members list, roles list and roles members list passed');
}finally{rmSync(home,{recursive:true,force:true})}
