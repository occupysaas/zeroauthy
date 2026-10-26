import {test,expect} from '@playwright/test';
import {createHash,randomBytes} from 'node:crypto';
import {api,publish,token,fixtureFetch} from './domains/client.mjs';
const ADMIN='https://system.e2e.test/admin/';
const PASSWORD='Domain-Operator-Password-2026';
test.use({proxy:{server:'http://127.0.0.1:9098'}});
async function ok(path,method,body){const r=await api(path,method,body);expect(r.status,JSON.stringify(r.body)).toBeLessThan(300);return r.body}
async function consoleLogin(page){
 await page.goto(process.env.E2E_ADMIN_SETUP_URL_M23);
 await page.fill('#password',PASSWORD);await page.fill('#password_confirm',PASSWORD);await page.click('button[type=submit]');
 await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto(ADMIN);await page.waitForURL(/\/u\/login/);
 await page.fill('#username','operator@e2e.local');await page.fill('#password',PASSWORD);await page.click('button[type=submit]');
 await page.waitForURL(/\/admin\/t\/.+/);
}
test('domain console: keyboard, narrow/wide, one-time secret, lost reply and stale tenant response',async({page})=>{
 test.setTimeout(120_000);test.skip(!process.env.E2E_ADMIN_SETUP_URL_M23,'Run make e2e-domains');
 await consoleLogin(page);
 const list=`${ADMIN}t/domains/custom-domains`;
 await page.goto(list);await expect(page.locator('#domain-name')).toBeVisible();
 for(const width of [390,1280]){
  await page.setViewportSize({width,height:900});
  await page.locator('#domain-name').focus();await page.keyboard.press('Tab');await expect(page.locator('#domain-type')).toBeFocused();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  await page.screenshot({path:`/tmp/zeroauthy-plan23-console-${width}.png`,fullPage:true});
 }
 await page.fill('#domain-name','browser.domains.e2e.test');await page.selectOption('#domain-type','self_managed_certs');
 await page.getByRole('button',{name:'Add domain',exact:true}).click();await expect(page.locator('h1')).toHaveText('browser.domains.e2e.test');
 const d=(await ok('custom-domains')).find(d=>d.domain==='browser.domains.e2e.test');await publish(d);
 await page.getByRole('button',{name:'Verify now',exact:true}).click();await expect(page.locator('[data-secret]')).toBeVisible();
 const key=await page.locator('[data-secret]').innerText();expect(key.length).toBeGreaterThan(30);
 const storage=await page.evaluate(()=>JSON.stringify({local:{...localStorage},session:{...sessionStorage},url:location.href}));expect(storage).not.toContain(key);
 await page.reload();await expect(page.locator('h1')).toHaveText(d.domain);await expect(page.locator('[data-secret]')).toHaveCount(0);
 await page.fill('#metadata','team=browser');await page.getByRole('button',{name:'Save settings',exact:true}).click();await expect(page.getByText('Settings saved.',{exact:true})).toBeVisible();
 const lost=await ok('custom-domains','POST',{domain:'lost.domains.e2e.test',type:'self_managed_certs'});await publish(lost);
 await page.goto(`${list}/${lost.custom_domain_id}`);
 let attempts=0;
 await page.route(`**/custom-domains/${lost.custom_domain_id}/verify`,async route=>{attempts++;await route.fetch();await route.abort('failed')});
 await page.getByRole('button',{name:'Verify now',exact:true}).click();await expect(page.getByText(/verification reply was lost/)).toBeVisible();
 expect(attempts).toBe(1);await expect(page.locator('[data-secret]')).toHaveCount(0);expect((await ok(`custom-domains/${lost.custom_domain_id}`)).status).toBe('ready');
 await page.unroute(`**/custom-domains/${lost.custom_domain_id}/verify`);
 // Delay an actual primary-tenant response, switch route/tenant, and deliver
 // that older response after the secondary request. No synthetic API data.
 let release;const gate=new Promise(r=>release=r);let captured;let delivered;const fulfilled=new Promise(r=>delivered=r);
 const seen=new Promise(r=>captured=r);
 await page.route('**/api/v2/custom-domains',async route=>{
  if(route.request().method()==='GET' && new URL(route.request().url()).hostname==='sdk.e2e.test'){
   const response=await route.fetch();captured();await gate;await route.fulfill({response});delivered();
  } else await route.continue();
 });
 await page.goto(list);await seen;
 await page.getByRole('button',{name:'Switch tenant',exact:true}).click();
 await page.getByRole('menuitem').filter({hasText:'Secondary domains'}).click();
 await page.getByRole('link',{name:'Custom domains',exact:true}).click();
 await expect(page).toHaveURL(/t\/secondary\/custom-domains/);
 release();await fulfilled;await page.unroute('**/api/v2/custom-domains');
 await expect(page.locator('h1')).toHaveText('Custom domains');await expect(page.getByRole('link',{name:d.domain,exact:true})).toHaveCount(0);
 await ok(`custom-domains/${d.custom_domain_id}`,'DELETE');await ok(`custom-domains/${lost.custom_domain_id}`,'DELETE');
});

test('public proxy domain: branding, PKCE issuer/audience, cross-host code and refresh rejection',async({browser})=>{
 test.setTimeout(90_000);test.skip(!process.env.E2E_ADMIN_SETUP_URL_M23,'Run make e2e-domains');
 const d=await ok('custom-domains','POST',{domain:'login.domains.e2e.test',type:'self_managed_certs',custom_client_ip_header:'cf-connecting-ip'});await publish(d);
 const v=await ok(`custom-domains/${d.custom_domain_id}/verify`,'POST');
 const origin=`https://${d.domain}`;
 const context=await browser.newContext({proxy:{server:'http://127.0.0.1:9098'},ignoreHTTPSErrors:true,extraHTTPHeaders:{'cname-api-key':v.cname_api_key,'cf-connecting-ip':'1.1.1.8'}});
 const page=await context.newPage();
 try {
  await ok('branding/templates/universal-login','PUT',{template:'<html><head>{% auth0:head %}</head><body><p>Domain welcome</p>{% auth0:widget %}</body></html>'});
  const user=await ok('users','POST',{email:'domain-user@e2e.local',password:'Domain-User-Password-2026',connection:'Username-Password-Authentication',email_verified:true});
  await context.route('https://callback.e2e.test/**',route=>route.fulfill({body:'callback'}));
  const verifier=randomBytes(32).toString('base64url');const challenge=createHash('sha256').update(verifier).digest('base64url');
  const params=new URLSearchParams({client_id:'m23-spa',response_type:'code',redirect_uri:'https://callback.e2e.test/',scope:'openid offline_access',state:'domain-state',nonce:'domain-nonce',code_challenge:challenge,code_challenge_method:'S256'});
  await page.goto(`${origin}/authorize?${params}`);await expect(page.getByText('Domain welcome',{exact:true})).toBeVisible();
  await page.fill('#username','domain-user@e2e.local');await page.fill('#password','Domain-User-Password-2026');await page.locator('form[action="/u/login"] button[type=submit]').click();
  await page.waitForURL('https://callback.e2e.test/**');const callback=new URL(page.url());expect(callback.searchParams.get('state')).toBe('domain-state');
  const code=callback.searchParams.get('code');expect(code).toBeTruthy();
  const redeem=async(domain,body,headers={})=>fixtureFetch(`https://${domain}/oauth/token`,{method:'POST',headers:{'content-type':'application/json','cf-connecting-ip':'1.1.1.8',...headers},body:JSON.stringify(body)});
  const body={grant_type:'authorization_code',client_id:'m23-spa',code,code_verifier:verifier,redirect_uri:'https://callback.e2e.test/'};
  expect((await redeem('sdk.e2e.test',body)).status).toBe(400);
  const response=await redeem(d.domain,body,{'cname-api-key':v.cname_api_key});const tokens=await response.json();expect(response.status,JSON.stringify(tokens)).toBe(200);
  const claims=JSON.parse(Buffer.from(tokens.id_token.split('.')[1],'base64url'));expect(claims.iss).toBe(origin+'/');expect(claims.aud).toBe('m23-spa');expect(claims.nonce).toBe('domain-nonce');
  const cookies=await context.cookies(origin);expect(cookies.length).toBeGreaterThan(0);expect(cookies.every(c=>c.domain===d.domain)).toBe(true);expect(await context.cookies('https://sdk.e2e.test')).toEqual([]);
  expect(tokens.refresh_token).toBeTruthy();
  {
   const refresh={grant_type:'refresh_token',client_id:'m23-spa',refresh_token:tokens.refresh_token};
   expect((await redeem('sdk.e2e.test',refresh)).status).toBe(400);
   expect((await redeem(d.domain,refresh,{'cname-api-key':v.cname_api_key})).status).toBe(200);
  }
  expect((await redeem(d.domain,body,{'cname-api-key':v.cname_api_key})).status).toBe(400);
  // Management audience stays pinned to the tenant's canonical identity even
  // when its access token is issued at the public domain.
  const machineResponse=await redeem(d.domain,{grant_type:'client_credentials',client_id:'m23-admin',client_secret:'m23-admin-secret-not-for-production',audience:'https://sdk.e2e.test/api/v2/'},{'cname-api-key':v.cname_api_key});
  const machine=await machineResponse.json();expect(machineResponse.status).toBe(200);
  const machineClaims=JSON.parse(Buffer.from(machine.access_token.split('.')[1],'base64url'));expect(machineClaims.iss).toBe(origin+'/');expect([machineClaims.aud].flat()).toContain('https://sdk.e2e.test/api/v2/');
  await ok('custom-domains/default','PATCH',{domain:d.domain});
  const reset=await ok('tickets/password-change','POST',{user_id:user.user_id});
  const verify=await ok('tickets/email-verification','POST',{user_id:user.user_id});
  expect(new URL(reset.ticket).origin).toBe(origin);expect(new URL(verify.ticket).origin).toBe(origin);
  await ok('custom-domains/default','PATCH',{domain:'sdk.e2e.test'});
  const canonical=await ok('tickets/password-change','POST',{user_id:user.user_id});expect(new URL(canonical.ticket).origin).toBe('https://sdk.e2e.test');
  await ok(`custom-domains/${d.custom_domain_id}`,'PATCH',{custom_client_ip_header:'cf-connecting-ip'});
  await context.setExtraHTTPHeaders({'cname-api-key':v.cname_api_key,'cf-connecting-ip':'1.1.1.9','x-forwarded-for':'10.0.0.7'});
  await ok('attack-protection/brute-force-protection','PATCH',{enabled:true,max_attempts:1,mode:'count_per_identifier_and_ip',shields:['block']});
  await page.goto(`${origin}/authorize?${params}&prompt=login`);
  await page.fill('#username','domain-user@e2e.local');await page.fill('#password','incorrect-domain-password');await page.locator('form[action="/u/login"] button[type=submit]').click();
  const blocks=await ok(`user-blocks/${encodeURIComponent(user.user_id)}`);
  expect(blocks.blocked_for.some(row=>row.ip==='1.1.1.9')).toBe(true);expect(blocks.blocked_for.some(row=>row.ip==='10.0.0.7')).toBe(false);
  // A ticket is bound when created; clearing the default cannot retarget it.
  await page.goto(reset.ticket);await expect(page.locator('#password')).toBeVisible();expect(new URL(page.url()).origin).toBe(origin);
 } finally {await context.close();await ok(`custom-domains/${d.custom_domain_id}`,'DELETE')}
});
