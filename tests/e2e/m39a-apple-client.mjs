import assert from 'node:assert/strict';
import {createPublicKey, verify} from 'node:crypto';
import {readFile, writeFile} from 'node:fs/promises';
import {ManagementClient} from 'auth0';
import {setGlobalDispatcher, Agent} from 'undici';
import {api, token, fixtureDispatcher, fixtureFetch} from './social/client.mjs';
export {api, token, fixtureFetch};
setGlobalDispatcher(fixtureDispatcher);
export const appleType='http://auth0.com/oauth/token-type/apple-authz-code';
export const exchangeGrant='urn:ietf:params:oauth:grant-type:token-exchange';
export const work=process.env.E2E_APPLE_WORK;
export const manager=async()=>new ManagementClient({domain:'sdk.e2e.test',token:await token(),maxRetries:0});
export async function control(route,body){const r=await fetch(`http://127.0.0.1:9173/apple/${route}`,{dispatcher:new Agent(),...(body?{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)}:{})});assert.equal(r.status,200);return r.json();}
export async function code(subject,client='test.apple.native'){return (await control('code',{Client:client,Subject:subject})).code;}
export async function localClaims(raw,client){
 assert.equal(typeof raw,'string');const [h,p,s]=raw.split('.');const header=JSON.parse(Buffer.from(h,'base64url'));assert.equal(header.alg,'RS256');
 const r=await fixtureFetch('https://sdk.e2e.test/.well-known/jwks.json');assert.equal(r.status,200);const jwks=await r.json();const key=jwks.keys.find(k=>k.kid===header.kid);assert.ok(key);
 assert.ok(verify('RSA-SHA256',Buffer.from(`${h}.${p}`),createPublicKey({key,format:'jwk'}),Buffer.from(s,'base64url')));
 const c=JSON.parse(Buffer.from(p,'base64url'));assert.equal(c.iss,'https://sdk.e2e.test/');assert.equal(c.aud,client);assert.ok(c.exp>Date.now()/1000);return c;
}
export async function persistPublic(name,data){await writeFile(`${work}/${name}.json`,JSON.stringify(data),{mode:0o600});}
export async function noAppleSecret(value){const key=await readFile(process.env.E2E_APPLE_KEY,'utf8');const s=JSON.stringify(value);assert.ok(!s.includes('PRIVATE KEY')&&!s.includes(key)&&!s.includes('app_secret'), 'Apple signing credential exposed');}
