import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,rmSync} from 'node:fs';
import {state} from './organizations/client.mjs';
const home=mkdtempSync('/tmp/za-m30-cli-');
const env={...process.env,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
function run(args,status=0){const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60000});assert.ok(!r.error,String(r.error));assert.equal(r.status,status,`${args.slice(0,3).join(' ')}: ${r.stderr}`);try{return JSON.parse(r.stdout)}catch{return r.stdout}}
try{
 assert.match(run(['--version']),/1\.37\.0/);
 const f=await state(),route=`organizations/${f.org}/invitations`;
 const invitation=run(['api','post',route,'--data',JSON.stringify({inviter:{name:'CLI operator'},invitee:{email:'plan30-cli@e2e.local'},client_id:'m24-spa',send_invitation_email:false})]);
 assert.equal(run(['api','get',`${route}/${invitation.id}`]).id,invitation.id);
 assert.ok(run(['api','get',route]).some(x=>x.id===invitation.id));
 run(['api','delete',`${route}/${invitation.id}`,'--force']);run(['api','get',`${route}/${invitation.id}`],1);
 console.log('Plan30 auth0-cli 1.37.0: raw api invitation create/get/list/delete passed; no native EA-command claim');
}finally{rmSync(home,{recursive:true,force:true})}
