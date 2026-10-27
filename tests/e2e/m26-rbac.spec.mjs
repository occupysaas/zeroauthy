import {test,expect} from '@playwright/test';
import {Agent} from 'undici';
import {api,audience,email,password,key,decode,state,fixtureFetch,protectedAPI} from './rbac/client.mjs';
import {authorization,upstreamLogin,complete} from './social/browser.mjs';

test.use({proxy:{server:'http://127.0.0.1:9198'}});
test.describe('Plan26 real RBAC tokens and console',()=>{
 test.skip(!process.env.E2E_M26,'Run make e2e-rbac');
 test.beforeEach(async({page})=>{await page.route('https://callback.e2e.test/**',r=>r.fulfill({status:200,body:'Application callback'}));});
 function flow(options={}){const f=authorization({audience,connection:'Username-Password-Authentication',...options});const u=new URL(f.url);u.searchParams.set('scope','openid profile email offline_access read:x');f.url=u.href;return f;}
 async function login(page,f){await page.goto(f.url);await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');return complete(page,f);}
 test('database PKCE issues current scope and revokes roles on refresh',async({page})=>{
  const f=await state();const {token}=await login(page,flow());
  expect(decode(token.access_token).permissions).toEqual(['read:x','write:x']);expect(token.scope).not.toContain('write:x');
  await protectedAPI(token.access_token);
  expect((await api(`users/${encodeURIComponent(f.user)}/roles`,'DELETE',{roles:[f.role]})).status).toBe(204);
  const r=await fixtureFetch('https://sdk.e2e.test/oauth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'refresh_token',client_id:'m24-spa',refresh_token:token.refresh_token})});
  expect(r.status).toBe(200);const refreshed=await r.json();expect(decode(refreshed.access_token).permissions).toEqual([]);expect(refreshed.scope.split(' ')).not.toContain('read:x');
  expect((await api(`users/${encodeURIComponent(f.user)}/roles`,'POST',{roles:[f.role]})).status).toBe(204);
 });
 test('federated PKCE gets permissions only after tenant role assignment',async({page})=>{
  const f=await state();expect((await api('connections','POST',{name:'google-oauth2',strategy:'google-oauth2',enabled_clients:['m24-spa'],options:{client_id:'m24-upstream-client',client_secret:'m24-upstream-secret-not-for-production',email:true,profile:true}})).status).toBe(201);
  let a=flow({connection:'google-oauth2'});await upstreamLogin(page,a,'google','rbac-google');let result=await complete(page,a);
  expect(decode(result.token.access_token).permissions).toEqual([]);expect(result.token.scope.split(' ')).not.toContain('read:x');
  expect((await api(`users/${encodeURIComponent(result.claims.sub)}/roles`,'POST',{roles:[f.role]})).status).toBe(204);
  await page.context().clearCookies();a=flow({connection:'google-oauth2'});await upstreamLogin(page,a,'google','rbac-google');result=await complete(page,a);
  expect(decode(result.token.access_token).permissions).toEqual(['read:x','write:x']);await protectedAPI(result.token.access_token);
 });
 test('custom domain keeps RBAC profile and issuer through PKCE exchange',async({page})=>{
  const created=await api('custom-domains','POST',{domain:'rbac.custom.e2e.test',type:'self_managed_certs',custom_client_ip_header:'cf-connecting-ip'});expect(created.status).toBe(201);
  const txt=created.body.verification.methods.find(x=>x.name==='txt');const proof=await fetch('http://127.0.0.1:9173/dns',{dispatcher:new Agent(),method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:txt.domain,value:txt.record})});expect(proof.status).toBe(204);
  const verified=await api(`custom-domains/${created.body.custom_domain_id}/verify`,'POST',{});expect(verified.status).toBe(200);expect(verified.body.status).toBe('ready');
  const headers={'cname-api-key':verified.body.cname_api_key,'cf-connecting-ip':'1.1.1.1'};await page.context().setExtraHTTPHeaders(headers);
  const a=flow({domain:'rbac.custom.e2e.test',connection:'Username-Password-Authentication'});await page.goto(a.url);await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');const {token}=await complete(page,a,{headers});
  const claims=decode(token.access_token);expect(claims.iss).toBe('https://rbac.custom.e2e.test/');expect(claims.permissions).toEqual(['read:x','write:x']);await protectedAPI(token.access_token,{issuer:claims.iss});
 });
 test('operator creates a role, grants a permission, assigns a user and deletes it',async({page})=>{
  test.setTimeout(120_000);const fixture=await state();
  await page.goto(process.env.E2E_M26_SETUP_URL);await page.fill('#password','Plan26-Operator-Password-2026');await page.fill('#password_confirm','Plan26-Operator-Password-2026');await page.click('button[type=submit]');await expect(page.locator('h1')).toHaveText('Password changed');
  await page.goto('https://system.e2e.test/admin/');await page.waitForURL(/\/u\/login/);await page.fill('#username','operator@e2e.local');await page.fill('#password','Plan26-Operator-Password-2026');await page.click('button[type=submit]');await page.waitForURL(/\/admin\/t\/.+/);
  await page.goto('https://system.e2e.test/admin/t/rbac/roles');await page.getByRole('link',{name:'Create role',exact:true}).click();
  await page.fill('#role-name','Browser Plan26 role');await page.fill('#role-description','Created through the console');await page.getByRole('button',{name:'Create role',exact:true}).click();await expect(page.locator('h1')).toHaveText('Browser Plan26 role');
  for(const width of [390,1280]){await page.setViewportSize({width,height:900});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);}
  await page.getByRole('tab',{name:'Permissions',exact:true}).click();await page.selectOption('#permission-api',audience);await page.selectOption('#permission-name','read:x');await page.getByRole('button',{name:'Add permission',exact:true}).click();await expect(page.locator('table')).toContainText('read:x');
  await page.getByRole('tab',{name:'Users',exact:true}).click();await page.fill('#role-user-id',fixture.user);await page.getByRole('button',{name:'Assign user',exact:true}).click();await expect(page.locator('table')).toContainText(email);
  await page.getByRole('tab',{name:'Settings',exact:true}).click();await page.getByRole('button',{name:'Delete role',exact:true}).click();await expect(page.getByRole('dialog')).toContainText('1 users');await page.getByRole('dialog').getByRole('button',{name:'Delete role',exact:true}).click();await expect(page).toHaveURL(/\/roles$/);await expect(page.getByRole('link',{name:'Browser Plan26 role',exact:true})).toHaveCount(0);
 });
});
