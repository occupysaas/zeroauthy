import {test,expect} from '@playwright/test';
import {api,email,password,decode,state} from './organizations/client.mjs';
import {authorization,complete} from './social/browser.mjs';

test.use({proxy:{server:'http://127.0.0.1:9198'}});
test.describe('Plan29 organization browser acceptance',()=>{
 test.skip(!process.env.E2E_M29,'Run make e2e-organizations');
 test.beforeEach(async({page})=>page.setDefaultTimeout(15_000));
 function flow({organization,client='m24-spa'}={}){const f=authorization({client,connection:'Username-Password-Authentication'});const u=new URL(f.url);if(organization)u.searchParams.set('organization',organization);f.url=u.href;return f;}
 async function credentials(page,username=email){await page.fill('#username',username);await page.fill('#password',password);await page.click('button[type=submit]');}
 async function screenshot(page,testInfo,name){await page.screenshot({path:testInfo.outputPath(`${name}.png`),fullPage:true});}
 test('pre-login organization prompt continues to branded login and issues organization tokens',async({page},testInfo)=>{
  const f=await state(),a=flow({client:'m29-pre'});await page.goto(a.url);await expect(page.locator('#organization')).toBeVisible();await screenshot(page,testInfo,'organization-prompt');
  await page.fill('#organization','alpha');await page.click('button[type=submit]');await expect(page.locator('#username')).toBeVisible();
  expect(await page.locator('body').evaluate(el=>getComputedStyle(el).backgroundColor)).toBe('rgb(240, 224, 208)');await screenshot(page,testInfo,'organization-login');
  await credentials(page);const result=await complete(page,a);expect(result.claims.org_id).toBe(f.alpha);expect(decode(result.token.access_token).org_id).toBe(f.alpha);
 });
 test('post-login picker presents two memberships and chooses the selected organization',async({page})=>{
  const f=await state(),a=flow({client:'m29-picker'});await page.goto(a.url);await credentials(page);
  await expect(page.getByRole('button',{name:'Alpha Organization',exact:true})).toBeVisible();await expect(page.getByRole('button',{name:'Beta Organization',exact:true})).toBeVisible();
  expect(await page.locator('button[name=organization]').count()).toBe(2);await page.getByRole('button',{name:'Beta Organization',exact:true}).click();expect((await complete(page,a)).claims.org_id).toBe(f.beta);
 });
 test('non-member receives access_denied without an authorization code',async({page})=>{
  const f=await state(),a=flow({organization:f.alpha});await page.goto(a.url);await credentials(page,'organizations-outsider@e2e.local');await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);
  const cb=new URL(page.url());expect(cb.searchParams.get('error')).toBe('access_denied');expect(cb.searchParams.has('code')).toBe(false);
 });
 test('automatic membership is persisted after real login',async({page})=>{
  const f=await state(),a=flow({organization:f.automatic});await page.goto(a.url);await credentials(page,'organizations-outsider@e2e.local');expect((await complete(page,a)).claims.org_id).toBe(f.automatic);
  expect((await api(`organizations/${f.automatic}/members`)).body.some(x=>x.user_id===f.outsider)).toBe(true);
 });
 test('organization signup creates both user and membership',async({page})=>{
  const f=await state(),a=flow({organization:f.signup});await page.goto(a.url);await page.locator('a[href^="/u/signup"]').click();await page.fill('#email','organization-signup@e2e.local');await page.fill('#password',password);await page.click('button[type=submit]');
  const result=await complete(page,a);expect(result.claims.org_id).toBe(f.signup);expect((await api(`organizations/${f.signup}/members`)).body.some(x=>x.user_id===result.claims.sub)).toBe(true);
 });
 test('auth0-spa-js loginWithRedirect validates org_id and returns the organization user',async({page})=>{
  const f=await state();await page.goto(`https://callback.e2e.test/org-spa?organization=${f.alpha}`);await page.waitForFunction(()=>window.ready||window.failure);expect(await page.evaluate(()=>window.failure)).toBeUndefined();
  await page.click('#login');await credentials(page);await page.waitForURL(/callback\.e2e\.test\/org-spa\?code=/);await page.waitForFunction(()=>window.claims||window.failure);expect(await page.evaluate(()=>window.failure)).toBeUndefined();expect(await page.evaluate(()=>window.claims.org_id)).toBe(f.alpha);expect(await page.evaluate(()=>window.user.email)).toBe(email);
 });
 test('operator manages organization settings branding connections members roles and application settings',async({page},testInfo)=>{
  test.setTimeout(180_000);const f=await state();
  await page.goto(process.env.E2E_M29_SETUP_URL);await page.fill('#password','Plan29-Operator-Password-2026');await page.fill('#password_confirm','Plan29-Operator-Password-2026');await page.click('button[type=submit]');await expect(page.locator('h1')).toHaveText('Password changed');
  await page.goto('https://system.e2e.test/admin/');await page.waitForURL(/\/u\/login/);await page.fill('#username','operator@e2e.local');await page.fill('#password','Plan29-Operator-Password-2026');await page.click('button[type=submit]');await page.waitForURL(/\/admin\/t\/.+/);
  await page.goto('https://system.e2e.test/admin/t/organizations/organizations');await expect(page.locator('h1')).toHaveText('Organizations');await screenshot(page,testInfo,'organizations-list');
  await page.getByRole('link',{name:'Create organization',exact:true}).click();await page.fill('#organization-name','browser-org');await page.fill('#organization-display-name','Browser Organization');await page.getByRole('button',{name:'Create organization',exact:true}).click();await expect(page.locator('h1')).toHaveText('Browser Organization');
  const orgID=new URL(page.url()).pathname.split('/').at(-1);
  await page.fill('#organization-metadata','{"source":"browser"}');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect(page.getByRole('status')).toContainText('Saved');expect((await api(`organizations/${orgID}`)).body.metadata).toEqual({source:'browser'});
  await page.fill('#organization-metadata','{}');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect.poll(async()=>(await api(`organizations/${orgID}`)).body.metadata).toBeUndefined();
  await page.getByRole('tab',{name:'Branding',exact:true}).click();await page.fill('#organization-primary','#234567');await page.fill('#organization-background','#eeeeee');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect(page.getByRole('status')).toContainText('Saved');await screenshot(page,testInfo,'organization-branding');
  await page.fill('#organization-primary','');await page.fill('#organization-background','');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect.poll(async()=>(await api(`organizations/${orgID}`)).body.branding).toBeUndefined();
  await page.getByRole('tab',{name:'Connections',exact:true}).click();await page.selectOption('#organization-connection',f.connection);await page.getByRole('button',{name:'Enable connection',exact:true}).click();await expect(page.locator('[data-flag=assign_membership_on_login]')).toBeVisible();await page.locator('[data-flag=assign_membership_on_login]').check();await expect(page.locator('[data-flag=is_signup_enabled]')).toBeEnabled();await page.locator('[data-flag=is_signup_enabled]').check();await expect(page.locator('[data-flag=is_signup_enabled]')).toBeChecked();await expect(page.locator('[data-flag=show_as_button]')).toBeDisabled();await screenshot(page,testInfo,'organization-connections');
  await page.getByRole('tab',{name:'Members',exact:true}).click();await page.fill('#organization-user-search',`email:"${email}"`);await page.getByRole('button',{name:'Search',exact:true}).click();await page.getByRole('button',{name:'Add member',exact:true}).click();await expect(page.getByRole('link',{name:email,exact:true})).toBeVisible();
  await page.getByRole('button',{name:'Member roles',exact:true}).click();await page.fill('#organization-role-id',f.role);await page.getByRole('button',{name:'Assign role',exact:true}).click();await expect(page.getByText('Plan29 Reader',{exact:true})).toBeVisible();await page.getByRole('button',{name:'Remove role',exact:true}).click();await expect(page.getByText('No member roles on this page',{exact:true})).toBeVisible();await screenshot(page,testInfo,'organization-members');
  await page.getByRole('link',{name:email,exact:true}).click();await page.getByRole('tab',{name:'Organizations',exact:true}).click();await expect(page.getByRole('link',{name:'Browser Organization',exact:true})).toBeVisible();await page.getByRole('link',{name:'Browser Organization',exact:true}).click();await page.getByRole('tab',{name:'Members',exact:true}).click();await page.getByRole('button',{name:'Remove member',exact:true}).click();await expect(page.getByText('No members on this page',{exact:true})).toBeVisible();
  await page.getByRole('tab',{name:'Connections',exact:true}).click();await page.getByRole('button',{name:'Remove connection',exact:true}).click();await expect(page.getByText('No associated connections on this page',{exact:true})).toBeVisible();
  await page.getByRole('tab',{name:'Settings',exact:true}).click();for(const width of [390,1280]){await page.setViewportSize({width,height:900});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);}
  await page.getByRole('button',{name:'Delete organization',exact:true}).click();await page.getByRole('dialog').getByRole('button',{name:'Delete organization',exact:true}).click();await expect(page).toHaveURL(/\/organizations$/);
  await page.goto('https://system.e2e.test/admin/t/organizations/applications/m24-spa');await page.getByRole('tab',{name:'Settings',exact:true}).click();await page.selectOption('#app-organization-usage','allow');await page.selectOption('#app-organization-behavior','pre_login_prompt');await page.check('#app-organization-discovery-organization_name');await page.getByRole('button',{name:'Save changes',exact:true}).click();await expect.poll(async()=>(await api('clients/m24-spa')).body.organization_require_behavior).toBe('pre_login_prompt');
 });
});
