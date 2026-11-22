// Original Plan 41a acceptance client; pinned node-auth0 against local HTTP.
import assert from 'node:assert/strict';
import {appendFile,readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {ManagementClient} from 'auth0';
export const work=process.env.E2E_M41A_WORK;
export const origin='https://localhost:9543',rp='https://127.0.0.1:9643';
export const credentials=work?JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8')):{};
export async function remember(value){assert.equal(typeof value,'string');await appendFile(`${work}/private-secrets.jsonl`,JSON.stringify(value)+'\n',{mode:0o600});return value;}
export async function tokens(fields){const r=await fetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(fields)});const body=await r.json();for(const key of ['access_token','id_token','refresh_token'])if(body[key])await remember(body[key]);return {status:r.status,body};}
export async function management(){const {status,body}=await tokens({grant_type:'client_credentials',client_id:'m41a-admin',client_secret:credentials.admin,audience:`${origin}/api/v2/`});assert.equal(status,200);return new ManagementClient({domain:'localhost:9543',token:body.access_token});}
export const decode=raw=>JSON.parse(Buffer.from(raw.split('.')[1],'base64url'));
async function run(){
 if(process.argv[2]==='audit'){
  const known=[...Object.values(credentials),...(await readFile(`${work}/private-secrets.jsonl`,'utf8')).trim().split('\n').filter(Boolean).map(s=>JSON.parse(s))];
  for(const name of ['server.log','playwright.log','browser-console.log']){let text;try{text=await readFile(`${work}/${name}`,'utf8')}catch(e){if(e.code==='ENOENT')continue;throw e}for(const value of known)assert.equal(text.includes(value),false,`${name} exposed a private value`);}
  console.log('Plan41a secret scan passed');return;
 }
 for(const value of Object.values(credentials))await remember(value);
 const m=await management();
 const settings={backchannel_logout_urls:['https://receiver.example.test/logout'],backchannel_logout_initiators:{mode:'custom',selected_initiators:['rp-logout','idp-logout','session-revoked']},backchannel_logout_session_metadata:{include:true}};
 const c=await m.clients.create({name:'Plan41a node-auth0 CRUD',app_type:'regular_web',jwt_configuration:{alg:'PS256'},oidc_logout:settings,oidc_support:{is_allowed:true,allowed_scopes:['email','phone']}});
 if(c.client_secret)await remember(c.client_secret);
 try{
  const got=await m.clients.get(c.client_id);assert.deepEqual(got.oidc_logout,settings);assert.equal(got.jwt_configuration.alg,'PS256');
  const updated=await m.clients.update(c.client_id,{jwt_configuration:{alg:'HS256'},oidc_support:{is_allowed:true,allow_all_scopes:true}});assert.equal(updated.jwt_configuration.alg,'HS256');
  const cleared=await m.clients.update(c.client_id,{oidc_logout:null,oidc_support:null});assert.equal(cleared.oidc_logout==null,true);assert.equal(cleared.oidc_support==null,true);
  await assert.rejects(()=>m.clients.update('m41a-spa',{jwt_configuration:{alg:'HS256'}}));
 }finally{await m.clients.delete(c.client_id)}
 console.log('Plan41a pinned node-auth0 OIDC/logout CRUD passed');
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===path.resolve(process.argv[1]))await run();
