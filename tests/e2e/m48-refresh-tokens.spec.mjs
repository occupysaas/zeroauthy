import {test,expect} from '@playwright/test';
import {appendFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {origin,redirect,API,SECOND,realm,email,secrets,pkce,key,proof,token,dpopToken,fixtureFetch,api,rawApi,decode,verifyResource,management,secret,work} from './m48-node-auth0.mjs';
test.skip(!process.env.E2E_M48_WORK,'Run make e2e-refresh-tokens');
test.use({trace:'off'});
const consoleWrites=[];
test.afterEach(async()=>{await Promise.all(consoleWrites.splice(0));});
async function browserContext(browser){const ctx=await browser.newContext({proxy:{server:'http://127.0.0.1:9198'},ignoreHTTPSErrors:true});await ctx.route('https://callback.e2e.test/**',r=>r.fulfill({status:200,body:'Plan48 local callback'}));const page=await ctx.newPage();page.on('console',m=>{const writing=appendFile(`${work}/browser-console.log`,m.text()+'\n');consoleWrites.push(writing);writing.catch(()=>{});});return {ctx,page};}
async function code(page,k,scope='openid email online_access',prompt='login'){
 const p=pkce();const u=new URL(`${origin}/authorize`);u.search=new URLSearchParams({client_id:'m48-public',response_type:'code',redirect_uri:redirect,scope,audience:API,code_challenge:p.challenge,code_challenge_method:'S256',state:'fixture48',dpop_jkt:k.jkt,prompt}).toString();await page.goto(u.href);
 if(prompt!=='none'&&!page.url().startsWith(redirect)){await page.fill('#username',email);await page.fill('#password',secrets().password);await page.locator('form[action="/u/login"] button[type=submit]').click();}
 await page.waitForURL(u=>u.href.startsWith(redirect));const callback=new URL(page.url());if(callback.searchParams.has('error'))return {error:callback.searchParams.get('error')};const value=callback.searchParams.get('code');expect(value).toBeTruthy();await secret(value);return {fields:{grant_type:'authorization_code',client_id:'m48-public',code:value,redirect_uri:redirect,code_verifier:p.verifier}};
}
async function userinfo(k,access,nonce){const jwt=await proof(k,`${origin}/userinfo`,nonce,access); // UserInfo POST exercises method and ath.
 const r=await fixtureFetch(`${origin}/userinfo`,{method:'POST',headers:{authorization:`DPoP ${access}`,DPoP:jwt}});return {r,body:await r.json(),jwt};}
test('public ORT: nonce/key binding, independent API verifier, UserInfo replay, invisibility, session metadata and logout',async({browser})=>{
 const {ctx,page}=await browserContext(browser);const k=key();try{
  const c=await code(page,k);const missing=await token(c.fields);expect(missing.body.error).toBe('invalid_dpop_proof');
  const t=await dpopToken(k,c.fields);expect(t.status).toBe(200);expect(t.body.token_type).toBe('DPoP');expect(t.body.refresh_token).toBeTruthy();
  await verifyResource(t.body.access_token,await proof(k,`${API}/resource`,undefined,t.body.access_token),k);
  const user=decode(t.body.access_token).sub,sid=decode(t.body.id_token).sid;expect(sid).toBeTruthy();const sdk=await management();
  const before=await sdk.sessions.get(sid);await sdk.sessions.update(sid,{session_metadata:{acceptance:'m48'}});expect((await sdk.sessions.get(sid)).session_metadata.acceptance).toBe('m48');
  const rows=await api(`refresh-tokens?user_id=${encodeURIComponent(user)}`);expect(rows.refresh_tokens.every(v=>v.client_id!=='m48-public')).toBe(true);
  const wrong=await dpopToken(key(),{grant_type:'refresh_token',client_id:'m48-public',refresh_token:t.body.refresh_token});expect(wrong.status).toBe(400);
  expect((await token({grant_type:'refresh_token',client_id:'m48-public',refresh_token:t.body.refresh_token})).body.error).toBe('invalid_dpop_proof');
  const r=await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:t.body.refresh_token},t.nonce);expect(r.status).toBe(200);expect(r.body.refresh_token===undefined,'online reuse must not return an opaque successor').toBe(true);const after=await sdk.sessions.get(sid);expect(after.expires_at).toBe(before.expires_at);expect(Date.parse(after.idle_expires_at)).toBeGreaterThanOrEqual(Date.parse(before.idle_expires_at));
  const ch=await userinfo(k,r.body.access_token,t.nonce);expect(ch.r.status).toBe(401);expect(ch.r.headers.get('www-authenticate')).toContain('use_dpop_nonce');const un=await secret(ch.r.headers.get('dpop-nonce'));const good=await userinfo(k,r.body.access_token,un);expect(good.r.status).toBe(200);expect(good.body.sub).toBe(user);
  const replay=await fixtureFetch(`${origin}/userinfo`,{method:'POST',headers:{authorization:`DPoP ${r.body.access_token}`,DPoP:good.jwt}});expect(replay.status).toBe(401);
  const bearer=await fixtureFetch(`${origin}/userinfo`,{headers:{authorization:`Bearer ${r.body.access_token}`}});expect(bearer.status).toBe(401);
  const wrongHash=await userinfo(k,t.body.id_token,un);expect(wrongHash.r.status).toBe(401);
  await page.goto(`${origin}/oidc/logout?${new URLSearchParams({id_token_hint:t.body.id_token,client_id:'m48-public',post_logout_redirect_uri:redirect})}`); // Logout is idempotent; the next token use is decisive.
  const dead=await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:t.body.refresh_token});expect(dead.body.error).toBe('invalid_grant');
 }finally{await ctx.close();}
});
test('online/offline conflict, explicit session revoke and bound ORT revoke end the browser SSO session',async({browser})=>{
 const {ctx,page}=await browserContext(browser);const k=key();try{
  const conflict=await code(page,k,'openid online_access offline_access');expect(conflict.error).toBe('invalid_request');
  const c=await code(page,k);const t=await dpopToken(k,c.fields);expect(t.status).toBe(200);const sid=decode(t.body.id_token).sid;const sdk=await management();await sdk.sessions.revoke(sid);expect((await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:t.body.refresh_token})).body.error).toBe('invalid_grant');
  const next=await code(page,k);const live=await dpopToken(k,next.fields);expect(live.status).toBe(200);
  const revokeBody={client_id:'m48-public',token:live.body.refresh_token};const revoke=async nonce=>fixtureFetch(`${origin}/oauth/revoke`,{method:'POST',headers:{'content-type':'application/json',DPoP:await proof(k,`${origin}/oauth/revoke`,nonce)},body:JSON.stringify(revokeBody)});
  let rr=await revoke();if(rr.status===400&&rr.headers.get('dpop-nonce'))rr=await revoke(await secret(rr.headers.get('dpop-nonce')));expect(rr.status).toBe(200);
  expect((await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:live.body.refresh_token})).body.error).toBe('invalid_grant');
  const silent=await code(page,k,'openid online_access','none');expect(silent.error).toBe('login_required');
 }finally{await ctx.close();}
});

test('ordinary session deletion invalidates online tokens and preserves offline tokens',async({browser})=>{
 const {ctx,page}=await browserContext(browser),k=key();try{
  const online=await dpopToken(k,(await code(page,k)).fields);expect(online.status).toBe(200);
  const offline=await dpopToken(k,(await code(page,k,'openid offline_access read:one','none')).fields);expect(offline.status).toBe(200);expect(offline.body.refresh_token).toBeTruthy();
  const sid=decode(online.body.id_token).sid;expect(decode(offline.body.id_token).sid).toBe(sid);await (await management()).sessions.delete(sid);
  expect((await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:online.body.refresh_token})).body.error).toBe('invalid_grant');
  expect((await dpopToken(k,{grant_type:'refresh_token',client_id:'m48-public',refresh_token:offline.body.refresh_token})).status).toBe(200);
 }finally{await ctx.close();}
});

test('rotating SPA SDK cache uses the refresh grant across two APIs', async ({browser}) => {
 const {ctx, page} = await browserContext(browser);
 const clientId = 'm48-spa-sdk';
 const bundle = fileURLToPath(new URL('./node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', import.meta.url));
 const init = async () => {
  await page.addScriptTag({path: bundle});
  await page.evaluate(options => { window.client = new auth0.Auth0Client(options); }, {
   domain: new URL(origin).hostname, clientId, cacheLocation: 'localstorage',
   useRefreshTokens: true, useRefreshTokensFallback: false, useMrrt: true,
   authorizationParams: {redirect_uri: redirect, audience: API, scope: {[API]: 'read:one', [SECOND]: 'read:two'}},
  });
 };
 const exchange = async action => {
  const [response, result] = await Promise.all([
   page.waitForResponse(r => r.url() === origin + '/oauth/token' && r.request().method() === 'POST'),
   action(),
  ]);
  expect(response.status()).toBe(200);
  const request = response.request().postDataJSON();
  const body = await response.json();
  for (const value of [request.code, request.code_verifier, body.id_token, body.access_token, body.refresh_token]) await secret(value);
  return {request, body, result};
 };
 try {
  await ctx.route(redirect + '**', r => r.fulfill({contentType: 'text/html', body: '<!doctype html><title>Plan 48 SDK fixture</title>'}));
  await page.goto(redirect);
  await init();
  await page.evaluate(audience => window.client.loginWithRedirect({authorizationParams: {audience, scope: 'read:one'}}), API);
  await page.locator('#username').fill(email);
  await page.locator('#password').fill(secrets().password);
  await page.locator('form[action="/u/login"] button[type=submit]').click();
  await page.waitForURL(u => u.origin === new URL(redirect).origin);
  await init();
  const initial = await exchange(() => page.evaluate(() => window.client.handleRedirectCallback()));
  expect(initial.request.grant_type).toBe('authorization_code');
  expect(typeof initial.body.refresh_token).toBe('string');
  expect(initial.body.scope.split(' ').sort()).toEqual(['offline_access', 'openid', 'read:one']);
  const user = decode(initial.body.access_token).sub;
  let previous = initial.body.refresh_token;
  let authorizeRequests = 0;
  page.on('request', r => { if (new URL(r.url()).pathname === '/authorize') authorizeRequests++; });
  for (const [audience, granted, excluded] of [[SECOND, 'read:two', 'read:one'], [API, 'read:one', 'read:two']]) {
   const {request, body, result} = await exchange(() => page.evaluate(audience =>
    window.client.getTokenSilently({authorizationParams: {audience}, cacheMode: 'off', detailedResponse: true}), audience));
   expect(request.grant_type).toBe('refresh_token');
   expect(request.audience).toBe(audience);
   expect(request.scope.split(' ')).toContain(granted);
   expect(request.refresh_token === previous, 'SDK must send its latest cached refresh token').toBe(true);
   expect(typeof body.refresh_token).toBe('string');
   expect(body.refresh_token !== previous, 'each refresh must rotate').toBe(true);
   expect(result.access_token === body.access_token, 'SDK returned the access token from this exchange').toBe(true);
   const claims = decode(result.access_token);
   expect([claims.aud].flat()).toContain(audience);
   expect(claims.scope.split(' ')).toContain(granted);
   expect(claims.scope.split(' ')).not.toContain(excluded);
   if (audience === SECOND) expect(claims.scope).toBe('read:two');
   previous = body.refresh_token;
  }
  expect(authorizeRequests).toBe(0);
  const list = await api('refresh-tokens?user_id=' + encodeURIComponent(user) + '&client_id=' + clientId);
  const rows = list.refresh_tokens.filter(row => row.client_id === clientId);
  expect(rows).toHaveLength(1);
  for (const row of rows) {
   expect(row.rotating).toBe(true);
   expect(row.resource_servers.map(resource => resource.audience)).toEqual([API]);
   expect(row.resource_servers[0].scopes.split(' ').sort()).toEqual(initial.body.scope.split(' ').sort());
  }
 } finally {
  await ctx.close();
 }
});
