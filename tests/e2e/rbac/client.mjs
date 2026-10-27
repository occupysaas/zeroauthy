import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Agent, setGlobalDispatcher } from 'undici';
import { fixtureFetch, fixtureDispatcher, api, token, primary } from '../social/client.mjs';
export { fixtureFetch, fixtureDispatcher, api, token, primary };
setGlobalDispatcher(fixtureDispatcher);
export const audience='https://rbac.e2e.test';
export const email='rbac-user@e2e.local';
export const password='Plan26-User-Password-2026';
export const key=name=>({resource_server_identifier:audience,permission_name:name});
export const decode=raw=>JSON.parse(Buffer.from(raw.split('.')[1],'base64url'));
export const state=async()=>JSON.parse(await readFile(process.env.E2E_M26_STATE,'utf8'));
export async function grant(extra={}){
 const r=await fixtureFetch(`https://${primary}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'password',client_id:'m26-password',client_secret:'m26-password-secret-not-for-production',username:email,password, audience,scope:'openid profile email offline_access read:x',...extra})});
 const body=await r.json();assert.equal(r.status,200,JSON.stringify(body));return body;
}
// The real middleware verifies signatures using the issuer's actual JWKS. A
// loopback JWKS relay only maps fixture DNS; it does not synthesize a key/token.
export async function protectedAPI(raw,{issuer=`https://${primary}/`,expectedRead=200,expectedWrite=403,expectedPermission=200}={}){
 const [{default:express},{auth,requiredScopes},{once}]=await Promise.all([import('express'),import('express-oauth2-jwt-bearer'),import('node:events')]);
 const jwks=await fixtureFetch(`https://${primary}/.well-known/jwks.json`);assert.equal(jwks.status,200);const keys=await jwks.json();
 const app=express();app.get('/jwks',(_,res)=>res.json(keys));
 const server=app.listen(0,'127.0.0.1');await once(server,'listening');
 const base=`http://127.0.0.1:${server.address().port}`;
 const check=auth({issuer,audience,jwksUri:`${base}/jwks`,tokenSigningAlg:'RS256'});
 app.get('/read',check,requiredScopes('read:x'),(_,res)=>res.sendStatus(200));
 app.get('/write',check,requiredScopes('write:x'),(_,res)=>res.sendStatus(200));
 app.get('/permission',check,(req,res)=>res.sendStatus(req.auth.payload.permissions?.includes('write:x')?200:403));
 app.use((err,req,res,next)=>{res.status(err.status??500).json({error:err.code??'verification_failed'});});
 try{for(const [route,status] of [['read',expectedRead],['write',expectedWrite],['permission',expectedPermission]]){
  const r=await fetch(`${base}/${route}`,{dispatcher:new Agent(),headers:{authorization:`Bearer ${raw}`}});assert.equal(r.status,status,`${route} with actual express-oauth2-jwt-bearer`);
 }}finally{server.close();await once(server,'close');}
}
