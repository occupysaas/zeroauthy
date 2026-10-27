import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api } from './social/client.mjs';
import { personas, upstreamSecret } from './social/email-accounts.mjs';
import { authorization, upstreamLogin, complete } from './social/browser.mjs';
test.use({proxy:{server:'http://127.0.0.1:9198'}});
test.describe('email account code and PKCE flows',()=>{
 test.skip(!process.env.E2E_M25,'Run make e2e-email-accounts');
 test.beforeEach(async({page})=>{await page.route('https://callback.e2e.test/**',r=>r.fulfill({status:200,body:'Application callback'}));});
 for(const [connection,flavor,subject,id] of personas) test(`${subject} via ${connection}: first and repeat`,async({page})=>{
  for(let i=0;i<2;i++){await page.context().clearCookies();const flow=authorization({connection});await upstreamLogin(page,flow,flavor,subject);const {claims}=await complete(page,flow);expect(claims.sub).toBe(id);}
 });
 for(const subject of ['tenant-mismatch','key-mismatch']) test(`Microsoft ${subject} fails without provisioning`,async({page})=>{
  const before=(await api('users')).body.length;
  await upstreamLogin(page,authorization({connection:'microsoft-directory'}),'11111111-1111-4111-8111-111111111111',subject);
  await expect(page.locator('body')).toContainText('could not');expect(page.url()).not.toContain('callback.e2e.test');expect((await api('users')).body.length).toBe(before);
 });
 test('Microsoft provider denial is sanitized',async({page})=>{await upstreamLogin(page,authorization({connection:'microsoft-personal'}),'consumers','outlook','Deny');await expect(page.locator('body')).toContainText('cancelled or refused');await expect(page.locator('body')).not.toContainText('mock user denied');});
 test('disable and secret rotation invalidate pending Microsoft attempts; reenable succeeds',async({page})=>{
  const c=(await api('connections?strategy=windowslive')).body[0];
  for(const rotation of [false,true]){
   await page.context().clearCookies();const flow=authorization({connection:c.name});await page.goto(flow.url);await expect(page).toHaveTitle('Mock consumers sign-in');const changed=rotation?await api(`connections/${c.id}`,'PATCH',{options:{...c.options,client_secret:'rotated-invalid-fixture-secret'}}):await api(`connections/${c.id}/clients`,'PATCH',[{client_id:'m24-spa',status:false}]);expect(changed.status,JSON.stringify(changed.body)).toBe(rotation?200:204);
   await page.fill('#subject','outlook');await page.getByRole('button',{name:'Allow',exact:true}).click();await expect(page.locator('body')).toContainText(/could not|expired or is invalid/);
   expect((await api(`connections/${c.id}`,'PATCH',{options:{...c.options,client_secret:upstreamSecret}})).status).toBe(200);expect((await api(`connections/${c.id}/clients`,'PATCH',[{client_id:'m24-spa',status:true}])).status).toBe(204);
  }
  await page.context().clearCookies();const flow=authorization({connection:c.name});await upstreamLogin(page,flow,'consumers','outlook');await complete(page,flow);
 });
 test('Microsoft custom-domain callback keeps origin and downstream issuer',async({page})=>{
  const {key}=JSON.parse(await readFile(process.env.E2E_M25_DOMAIN_FILE,'utf8'));const headers={'cname-api-key':key,'cf-connecting-ip':'1.1.1.1'};
  // Simulate the trusted reverse proxy for this isolated browser context,
  // including redirects (Playwright route header overrides omit redirected callbacks).
  await page.context().setExtraHTTPHeaders(headers);
  let callback='';page.on('request',r=>{if(r.url().includes('/login/callback?'))callback=r.url();});
  const flow=authorization({domain:'email.custom.e2e.test',connection:'microsoft-personal'});await upstreamLogin(page,flow,'consumers','outlook');await complete(page,flow,{headers});expect(callback).toMatch(/^https:\/\/email\.custom\.e2e\.test\/login\/callback\?/);
 });
});
