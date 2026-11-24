// Plan 38a (make e2e-ad): the pinned node-auth0 SDK against zeroauthy with
// the real AD/LDAP Connector. Modes: setup (create the ad connection, save
// its provisioning ticket), online (wait for status 200), user (the user the
// login provisioned), password (change it through the connector), offline
// (status 404 after the connector stops).
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {ManagementClient} from 'auth0';
const work=process.env.E2E_M38A_WORK;
const domain='localhost:9565';
const creds=JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8'));
async function token(){
 const r=await fetch(`https://${domain}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({grant_type:'client_credentials',client_id:'m38a-admin',client_secret:creds.admin,audience:`https://${domain}/api/v2/`})});
 const out=await r.json();assert.equal(r.status,200,JSON.stringify(out));return out.access_token;
}
const client=new ManagementClient({domain,token:await token(),maxRetries:0});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const state=async()=>JSON.parse(await readFile(`${work}/connection.json`,'utf8'));
const mode=process.argv[2];
if(mode==='setup'){
 const conn=await client.connections.create({name:'corp-ad',strategy:'ad',enabled_clients:['m38a-spa'],
  options:{tenant_domain:'example.org',domain_aliases:['example.org'],certs:['client-sent'],agentVersion:'9.9.9'}});
 assert.equal(conn.strategy,'ad');
 assert.match(conn.provisioning_ticket_url,/^https:\/\/localhost:9565\/p\/ad\/[A-Za-z0-9]{32}$/);
 assert.equal(conn.options.certs,undefined,'connector-managed options are not writable');
 assert.equal(conn.options.brute_force_protection,true);
 await assert.rejects(client.connections.checkStatus(conn.id),e=>e.statusCode===404);
 await writeFile(`${work}/connection.json`,JSON.stringify({id:conn.id}),{mode:0o600});
 await writeFile(`${work}/ticket`,conn.provisioning_ticket_url,{mode:0o600});
 console.log('Plan 38a SDK: ad connection created with a provisioning ticket; status 404 before a connector');
}else if(mode==='online'){
 const {id}=await state();
 for(let i=0;;i++){
  try{await client.connections.checkStatus(id);break}catch(e){if(e.statusCode!==404||i>=180)throw e}
  await sleep(1000);
 }
 const conn=await client.connections.get(id);
 assert.equal(conn.options.certs.length,1);assert.equal(conn.options.thumbprints.length,1);assert.equal(conn.options.thumbprints_sha384[0].length,96);
 assert.equal(conn.options.signInEndpoint,'http://127.0.0.1:4001/wsfed');assert.equal(conn.options.agentMode,true);
 assert.ok(conn.options.agentIP,'agentIP recorded');
 // An export re-imported keeps the connector's certificate (LR38a-6).
 await client.connections.update(id,{options:{...conn.options,certs:['replaced']}});
 assert.deepEqual((await client.connections.get(id)).options.certs,conn.options.certs);
 console.log('Plan 38a SDK: the real connector registered and connected (status 200)');
}else if(mode==='user'){
 const user=await client.users.get('ad|corp-ad|jdoe');
 assert.equal(user.email,'jdoe@example.org');assert.equal(user.identities[0].provider,'ad');assert.equal(user.identities[0].isSocial,false);
 assert.equal(user.identities[0].user_id,'corp-ad|jdoe');
 assert.deepEqual([...user.identities[0].profileData.groups].sort(),['administrators','users']);
 const escaped=await client.users.get('ad|corp-ad|jd()e');assert.equal(escaped.email,'jd()e@example.org');
 console.log('Plan 38a SDK: provisioned users with directory groups');
}else if(mode==='password'){
 await client.users.update('ad|corp-ad|jdoe',{password:creds.newPassword,connection:'corp-ad'});
 console.log('Plan 38a SDK: password changed in the directory through the connector');
}else if(mode==='offline'){
 const {id}=await state();
 for(let i=0;;i++){
  try{await client.connections.checkStatus(id)}catch(e){if(e.statusCode===404)break;throw e}
  if(i>=60)throw new Error('still online after the connector stopped');
  await sleep(1000);
 }
 console.log('Plan 38a SDK: status 404 after the connector stopped');
}else throw new Error(`unknown mode ${mode}`);
