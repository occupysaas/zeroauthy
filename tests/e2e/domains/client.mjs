import assert from 'node:assert/strict';
import { ProxyAgent } from 'undici';
export const fixtureDispatcher = new ProxyAgent('http://127.0.0.1:9098');
export const fixtureFetch = (url, options = {}) => fetch(url, { dispatcher: fixtureDispatcher, ...options });
export const replicaDispatcher = new ProxyAgent('http://127.0.0.1:9099');
export const primary = 'sdk.e2e.test';
export async function token(domain = primary, scope) {
 const r = await fixtureFetch(`https://${domain}/oauth/token`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({grant_type:'client_credentials',client_id:'m23-admin',client_secret:'m23-admin-secret-not-for-production',audience:`https://${domain}/api/v2/`,...(scope ? {scope} : {})}) });
 const out = await r.json(); assert.equal(r.status,200,JSON.stringify(out)); return out.access_token;
}
export async function api(path, method='GET', body, domain=primary, bearer) {
 const r = await fixtureFetch(`https://${domain}/api/v2/${path}`, {method,headers:{authorization:`Bearer ${bearer ?? await token(domain)}`,'content-type':'application/json'},...(body===undefined ? {} : {body:JSON.stringify(body)})});
 const out=await r.json().catch(()=>undefined); return {status:r.status,body:out,headers:r.headers};
}
export async function publish(d) {
 const rec=d.verification.methods[0];
 // Use a separate direct dispatcher: the CONNECT fixture refuses all hosts
 // except *.e2e.test:443, and the DNS control listener is loopback only.
 const { Agent } = await import('undici');
 const r=await fetch('http://127.0.0.1:9073/dns',{dispatcher:new Agent(),method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:rec.domain,value:rec.record})});
 assert.equal(r.status,204);
}
export function noSecret(value) {
 assert.ok(!JSON.stringify(value).match(/cname_api_key|proxy_key_hash|private_key|ciphertext|proof_token/i));
}
