// Original Plan 48 local acceptance helpers. Pinned SDKs are test clients only.
import assert from 'node:assert/strict';
import https from 'node:https';
import {createHash, generateKeyPairSync, randomBytes, randomUUID, sign, verify, createPublicKey} from 'node:crypto';
import {readFile, writeFile, appendFile} from 'node:fs/promises';
import {ManagementClient} from 'auth0';
import {AuthClient} from '@auth0/auth0-auth-js';

export const work=process.env.E2E_M48_WORK;
export const origin='https://refresh.e2e.test', redirect='https://callback.e2e.test/';
export const API='https://api.refresh.e2e.test', SECOND='https://second.refresh.e2e.test';
export const realm='Username-Password-Authentication', email='refresh48@e2e.local';
export const secrets=()=>JSON.parse(process.env.E2E_M48_CREDENTIALS);
const watched=new Set();
export async function secret(v){if(typeof v==='string'&&v.length>8&&!watched.has(v)){watched.add(v);await appendFile(`${work}/private-values.jsonl`,JSON.stringify(v)+'\n',{mode:0o600});}return v;}
export function fixtureFetch(input,opts={}) {
 const url=new URL(input instanceof Request?input.url:String(input));
 assert.equal(url.origin,origin,'fixture refuses outbound destinations');
 return new Promise((resolve,reject)=>{
  const headers=Object.fromEntries(new Headers(opts.headers??(input instanceof Request?input.headers:undefined)));
  const req=https.request({hostname:'127.0.0.1',port:9543,servername:url.hostname,method:opts.method??'GET',path:url.pathname+url.search,headers:{...headers,host:url.host}},res=>{
   let body='';res.setEncoding('utf8');res.on('data',v=>body+=v);res.on('end',()=>resolve(new Response([204,205,304].includes(res.statusCode)?null:body,{status:res.statusCode,headers:res.headers})));
  });req.on('error',reject);req.setTimeout(45000,()=>req.destroy(new Error('local fixture HTTP timeout')));if(opts.body)req.write(opts.body instanceof URLSearchParams?opts.body.toString():opts.body);req.end();
 });
}
export async function token(fields,headers={}){
 if(fields.client_secret)await secret(fields.client_secret);
 const r=await fixtureFetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams(fields)});
 const body=await r.json();for(const k of ['access_token','refresh_token','id_token'])await secret(body[k]);
 return {status:r.status,body,headers:r.headers};
}
let admin;
export async function adminToken(){if(!admin){const r=await token({grant_type:'client_credentials',client_id:'m48-admin',client_secret:secrets().admin,audience:`${origin}/api/v2/`});assert.equal(r.status,200,'management authentication');admin=r.body.access_token;}return admin;}
export async function rawApi(route,method='GET',body){const r=await fixtureFetch(`${origin}/api/v2/${route}`,{method,headers:{authorization:`Bearer ${await adminToken()}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});return {status:r.status,body:r.status===204?null:await r.json()};}
export async function api(route,method='GET',body){const r=await rawApi(route,method,body);assert.ok(r.status>=200&&r.status<300,`${method} ${route}: ${r.status}`);return r.body;}
export const management=async()=>new ManagementClient({domain:'refresh.e2e.test',token:await adminToken(),maxRetries:0,fetch:fixtureFetch});
export const decode=t=>JSON.parse(Buffer.from(t.split('.')[1],'base64url'));
export const pkce=()=>{const verifier=randomBytes(32).toString('base64url');return {verifier,challenge:createHash('sha256').update(verifier).digest('base64url')};};
export function key(){const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});const jwk=publicKey.export({format:'jwk'});const jkt=createHash('sha256').update(JSON.stringify({crv:jwk.crv,kty:jwk.kty,x:jwk.x,y:jwk.y})).digest('base64url');return {privateKey,jwk,jkt};}
export async function proof(k,url,nonce,accessToken){const h=Buffer.from(JSON.stringify({typ:'dpop+jwt',alg:'ES256',jwk:k.jwk})).toString('base64url');const p=Buffer.from(JSON.stringify({jti:randomUUID(),htm:'POST',htu:url,iat:Math.floor(Date.now()/1000),...(nonce?{nonce}:{}),...(accessToken?{ath:createHash('sha256').update(accessToken).digest('base64url')}:{})})).toString('base64url');const jwt=`${h}.${p}.${sign('sha256',Buffer.from(`${h}.${p}`),{key:k.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url')}`;await secret(jwt);return jwt;}
export async function dpopToken(k,fields,nonce){let r=await token(fields,{DPoP:await proof(k,`${origin}/oauth/token`,nonce)});if(r.body.error==='use_dpop_nonce'){nonce=await secret(r.headers.get('dpop-nonce'));r=await token(fields,{DPoP:await proof(k,`${origin}/oauth/token`,nonce)});}return {...r,nonce};}
// A standalone resource verifier fixture checks actual signature, issuer,
// audience and key confirmation; this is independent of the server's verifier.
export async function verifyResource(accessToken,proofJWT,k){const meta=await (await fixtureFetch(`${origin}/.well-known/jwks.json`)).json();const [h,p,s]=accessToken.split('.'),head=JSON.parse(Buffer.from(h,'base64url'));const jwk=meta.keys.find(v=>v.kid===head.kid);assert.ok(jwk);assert.equal(verify('RSA-SHA256',Buffer.from(`${h}.${p}`),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(s,'base64url')),true);const claims=decode(accessToken);assert.equal(claims.iss,`${origin}/`);assert.ok([claims.aud].flat().includes(API));assert.ok(claims.exp> Date.now()/1000);assert.equal(claims.cnf.jkt,k.jkt);const [ph,pp,ps]=proofJWT.split('.');assert.equal(verify('sha256',Buffer.from(`${ph}.${pp}`),{key:createPublicKey({key:k.jwk,format:'jwk'}),dsaEncoding:'ieee-p1363'},Buffer.from(ps,'base64url')),true);const pc=JSON.parse(Buffer.from(pp,'base64url'));assert.equal(pc.ath===createHash('sha256').update(accessToken).digest('base64url'),true,'resource proof must bind the returned access token');assert.equal(pc.htu,`${API}/resource`);}
export async function passwordToken(extra={}){return token({grant_type:'password',client_id:'m48-web',client_secret:secrets().web,username:email,password:secrets().password,scope:'openid email offline_access read:one',audience:API,...extra});}
export async function setup(){await secret(secrets().password);await api('users','POST',{connection:realm,email,password:secrets().password,email_verified:true});console.log('Plan48 synthetic user prepared');}
export function assertRefreshTokenChanged(next,previous){assert.equal(next!==previous,true,'conversion must replace the opaque refresh token');}
export async function sdkAndProtocols(){
 const sdk=await management();const first=await passwordToken();assert.equal(first.status,200,'offline issue');const user=decode(first.body.access_token).sub;
 const listed=await sdk.refreshTokens.list({user_id:user});const items=[];for await(const row of listed)items.push(row);assert.ok(items.length>0,'node-auth0 list');const id=items.find(v=>v.client_id==='m48-web').id;
 await sdk.refreshTokens.update(id,{refresh_token_metadata:{fixture:'sdk'}});assert.equal((await sdk.refreshTokens.get(id)).refresh_token_metadata.fixture,'sdk');
 const auth=new AuthClient({domain:'refresh.e2e.test',clientId:'m48-web',clientSecret:secrets().web,customFetch:fixtureFetch});
 const refreshed=await auth.getTokenByRefreshToken({refreshToken:first.body.refresh_token});assert.ok(refreshed.accessToken,'auth-js refresh');await secret(refreshed.accessToken);const history=await sdk.refreshTokens.get(id);assert.equal(typeof history.device.initial_user_agent,'string');assert.ok(history.last_exchanged_at,'successful SDK exchange recorded');
 await api('clients/m48-web','PATCH',{refresh_token:{policies:[{audience:SECOND,scope:['read:two']}]}});
 const other=await token({grant_type:'refresh_token',client_id:'m48-web',client_secret:secrets().web,refresh_token:first.body.refresh_token,audience:SECOND,scope:'read:two forbidden'});assert.equal(other.status,200);assert.equal(decode(other.body.access_token).aud,SECOND);assert.equal(other.body.scope,'read:two');
 const own=await token({grant_type:'refresh_token',client_id:'m48-web',client_secret:secrets().web,refresh_token:first.body.refresh_token});assert.equal(own.status,200);assert.ok(!own.body.scope.includes('read:two'),'family ceiling unchanged');
 await api('clients/m48-web','PATCH',{refresh_token:{policies:null,rotation_type:'rotating',expiration_type:'expiring',leeway:30}});
 const converted=await token({grant_type:'refresh_token',client_id:'m48-web',client_secret:secrets().web,refresh_token:first.body.refresh_token});assert.equal(converted.status,200);assert.ok(converted.body.refresh_token);assertRefreshTokenChanged(converted.body.refresh_token,first.body.refresh_token);
 const exchange=rt=>token({grant_type:'refresh_token',client_id:'m48-web',client_secret:secrets().web,refresh_token:rt});
 const next=await exchange(converted.body.refresh_token);assert.equal(next.status,200);const newest=await exchange(next.body.refresh_token);assert.equal(newest.status,200);assert.equal((await exchange(converted.body.refresh_token)).body.error,'invalid_grant');assert.equal((await exchange(newest.body.refresh_token)).body.error,'invalid_grant');
 const rotating=await passwordToken();assert.equal(rotating.status,200);await api('clients/m48-web','PATCH',{refresh_token:{rotation_type:'non-rotating'}});const plain=await exchange(rotating.body.refresh_token);assert.equal(plain.status,200);assert.ok(plain.body.refresh_token);assert.equal((await exchange(rotating.body.refresh_token)).body.error,'invalid_grant');
 await api('clients/m48-quota','PATCH',{token_quota:{client_credentials:{per_hour:3,per_day:10}}});const requests=await Promise.all(Array.from({length:8},()=>token({grant_type:'client_credentials',client_id:'m48-quota',client_secret:secrets().quota,audience:API,scope:'read:one'})));assert.equal(requests.filter(v=>v.status===200).length,3);assert.equal(requests.filter(v=>v.status===429).length,5);const accepted=requests.find(v=>v.status===200),refused=requests.find(v=>v.status===429);assert.match(accepted.headers.get('auth0-client-quota-limit'),/^b=per_hour;q=3;r=\d;t=\d+,b=per_day;q=10;r=\d;t=\d+$/);assert.equal(refused.headers.get('x-ratelimit-remaining'),'0');assert.ok(Number(refused.headers.get('retry-after'))>0);assert.equal(refused.body.error,'too_many_requests');
 await api('tenants/settings','PATCH',{flags:{revoke_refresh_token_grant:true}});const sibling=await passwordToken();await fixtureFetch(`${origin}/oauth/revoke`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_id:'m48-web',client_secret:secrets().web,token:plain.body.refresh_token})});assert.equal((await exchange(sibling.body.refresh_token)).body.error,'invalid_grant');
 const refusedSelector=await rawApi('refresh-tokens/revoke','POST',{client_id:'m48-web'});assert.equal(refusedSelector.status,400);const offline=await passwordToken();assert.equal(offline.status,200);const rs=(await api('resource-servers')).find(v=>v.identifier===API);await api(`resource-servers/${rs.id}`,'PATCH',{allow_offline_access:false});const denied=await exchange(offline.body.refresh_token);assert.equal(denied.body.error,'invalid_grant');await api(`resource-servers/${rs.id}`,'PATCH',{allow_offline_access:true});await sdk.refreshTokens.revoke({user_id:user,client_id:'m48-web'});
 console.log('Plan48 node-auth0/auth-js: metadata, MRRT, conversion, strict reuse, cascade and concurrent quotas passed');
}
export async function audit(directory=work){const vals=(await readFile(`${directory}/private-values.jsonl`,'utf8')).trim().split('\n').filter(Boolean).map(JSON.parse);for(const file of ['server.log','browser-console.log','cli.log','stored-sinks.jsonl']){const text=await readFile(`${directory}/${file}`,'utf8');for(const v of vals)assert.equal(text.includes(v),false,`${file} leaked representative secret`);}console.log('Plan48 representative-secret log audit passed');}
if(process.argv[1]?.endsWith('/m48-node-auth0.mjs')){const phase=process.argv[2];if(phase==='setup')await setup();else if(phase==='sdk')await sdkAndProtocols();else if(phase==='audit')await audit();else throw Error('unknown Plan48 phase');}
