import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { ProxyAgent } from 'undici';

// The only completion route is the provider callback followed by the actual
// downstream authorization-code + PKCE token request. No session insertion.
export function authorization({domain='sdk.e2e.test',client='m24-spa',connection,audience}={}) {
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex');
 const redirect='https://callback.e2e.test/';
 const query=new URLSearchParams({client_id:client,redirect_uri:redirect,response_type:'code',scope:'openid profile email',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',connection,...(audience?{audience}: {})});
 return {url:`https://${domain}/authorize?${query}`,domain,client,redirect,verifier,state,nonce};
}
export async function upstreamLogin(page,flow,flavor,subject,decision='Allow') {
 await page.goto(flow.url);
 assert.equal(await page.title(),`Mock ${flavor} sign-in`);
 const upstream=new URL(page.url());assert.equal(upstream.searchParams.get('code_challenge_method'),'S256');assert.ok(upstream.searchParams.get('state'));assert.ok(upstream.searchParams.get('nonce'));
 await page.fill('#subject',subject);await page.getByRole('button',{name:decision,exact:true}).click();
}
export async function complete(page,flow,{proxy='http://127.0.0.1:9198',headers={}}={}) {
 await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);
 const cb=new URL(page.url());assert.equal(cb.searchParams.get('state'),flow.state);assert.ok(cb.searchParams.get('code'));
 const response=await fetch(`https://${flow.domain}/oauth/token`,{dispatcher:new ProxyAgent(proxy),method:'POST',headers:{'content-type':'application/json',...headers},body:JSON.stringify({grant_type:'authorization_code',client_id:flow.client,redirect_uri:flow.redirect,code:cb.searchParams.get('code'),code_verifier:flow.verifier})});
 const token=await response.json();assert.equal(response.status,200,JSON.stringify(token));assert.ok(token.access_token);assert.ok(token.id_token);
 const claims=JSON.parse(Buffer.from(token.id_token.split('.')[1],'base64url'));assert.equal(claims.nonce,flow.nonce);assert.equal(claims.iss,`https://${flow.domain}/`);assert.equal(claims.aud,flow.client);
 return {token,claims};
}
