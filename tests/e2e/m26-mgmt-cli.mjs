// Pinned Auth0 CLI 1.37.0 talks to zeroauthy's real RBAC routes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { state,key } from './rbac/client.mjs';
const home=mkdtempSync('/tmp/za-m26-cli-');
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
function run(args,status=0){const r=spawnSync(process.env.AUTH0_BIN,[...args,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60_000});assert.ok(!r.error,`${r.error}`);assert.equal(r.status,status,`${args.slice(0,3).join(' ')}: ${r.stderr}`);try{return JSON.parse(r.stdout)}catch{return r.stdout}}
try{
 const fixture=await state();
 const role=run(['api','post','roles','--data',JSON.stringify({name:'CLI Plan26 role',description:'CLI fixture'})]);
 assert.equal(run(['api','get',`roles/${role.id}`]).name,'CLI Plan26 role');
 run(['api','patch',`roles/${role.id}`,'--data',JSON.stringify({description:'Updated CLI'})]);
 run(['api','post',`roles/${role.id}/permissions`,'--data',JSON.stringify({permissions:[key('read:x')]})]);
 assert.equal(run(['api','get',`roles/${role.id}/permissions`]).length,1);
 run(['api','post',`roles/${role.id}/users`,'--data',JSON.stringify({users:[fixture.user]})]);
 assert.equal(run(['api','get',`roles/${role.id}/users`])[0].user_id,fixture.user);
 assert.ok(run(['api','get',`users/${encodeURIComponent(fixture.user)}/roles`]).some(r=>r.id===role.id));
 run(['api','delete',`users/${encodeURIComponent(fixture.user)}/roles`,'--data',JSON.stringify({roles:[role.id]})]);
 run(['api','delete',`roles/${role.id}/permissions`,'--data',JSON.stringify({permissions:[key('read:x')]})]);
 run(['api','delete',`roles/${role.id}`]);run(['api','get',`roles/${role.id}`],1);
 console.log('m26 Auth0 CLI 1.37.0: role CRUD, API permissions, member assignment and removal passed');
}finally{rmSync(home,{recursive:true,force:true})}
