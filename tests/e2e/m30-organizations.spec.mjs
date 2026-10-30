import {test,expect} from '@playwright/test';
import {Agent} from 'undici';
import {state,api,password,fixtureFetch,decode} from './organizations/client.mjs';
import {management,bind} from './m27-node-auth0.mjs';
import {authorization,complete} from './social/browser.mjs';
test.skip(!process.env.E2E_M30,'Run make e2e-organizations-ii');
test.use({proxy:{server:'http://127.0.0.1:9198'}});
const sink=()=>fetch('http://127.0.0.1:9173/m28/sink',{dispatcher:new Agent()}).then(r=>r.json());
async function credentials(page,email){await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');}
async function invite(email){const f=await state(),m=await management();return m.organizations.invitations.create(f.org,{inviter:{name:'Browser operator'},invitee:{email},client_id:'m24-spa',connection_id:f.connection,send_invitation_email:false});}
async function appFlow(page,url){await page.goto(url);await expect(page.locator('#username')).toBeVisible();}
async function applicationState(page){await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);return JSON.parse(await page.evaluate(()=>sessionStorage.getItem('m30-flow')));}
async function postToken(body){const r=await fixtureFetch('https://sdk.e2e.test/oauth/token',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return {status:r.status,body:await r.json()};}
test('captured invitation follows application signup, normal email verification, retry, Actions and PKCE exchange; replay rejected',async({page})=>{
 test.setTimeout(120000);const f=await state();
 await expect.poll(async()=>(await sink()).filter(x=>x.kind==='mail'&&x.notification.to==='plan30-new@e2e.local'&&x.notification.message_type==='user_invitation').length,{timeout:60000}).toBe(1);
 const mail=(await sink()).find(x=>x.notification?.message_type==='user_invitation');
 const href=mail.notification.html.match(/href="([^"]*invitation-login[^\"]*)"/)[1].replaceAll('&amp;','&');
 expect(new URL(href).searchParams.get('organization')).toBe(f.org);expect(href).toBe(f.invitation.invitation_url);
 await appFlow(page,href);await page.locator('a[href^="/u/signup"]').click();await page.fill('#email','plan30-new@e2e.local');await page.fill('#password',password);await page.click('button[type=submit]');
 await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);expect(new URL(page.url()).searchParams.get('error')).toBe('access_denied');
 expect((await api(`organizations/${f.org}/members`)).body).toHaveLength(0);
 await expect.poll(async()=>(await sink()).filter(x=>x.notification?.to==='plan30-new@e2e.local'&&x.notification.message_type==='verify_email').length,{timeout:60000}).toBe(1);
 const verification=(await sink()).find(x=>x.notification?.message_type==='verify_email');const verifyURL=verification.notification.html.match(/href="([^\"]*\/u\/email-verification[^\"]*)"/)[1].replaceAll('&amp;','&');
 await page.goto(verifyURL);await expect(page.locator('body')).toContainText(/verified|verification/i);
 await page.context().clearCookies();await appFlow(page,href);await credentials(page,'plan30-new@e2e.local');const result=await complete(page,await applicationState(page));
 expect(result.claims.org_id).toBe(f.org);expect(result.claims['https://plan30.test/org']).toBe(f.org);expect(decode(result.token.access_token).org_id).toBe(f.org);
 expect((await api(`organizations/${f.org}/members`)).body.some(x=>x.user_id===result.claims.sub)).toBe(true);
 await page.context().clearCookies();await page.goto(href);await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);expect(new URL(page.url()).searchParams.get('error')).toBeTruthy();expect(new URL(page.url()).searchParams.has('code')).toBe(false);
});
test('wrong account leaves invitation usable by intended verified account',async({page})=>{
 const m=await management(),f=await state();for(const email of ['wrong30@e2e.local','right30@e2e.local'])await m.users.create({connection:'Username-Password-Authentication',email,password,email_verified:true});
 const invitation=await invite('right30@e2e.local');await appFlow(page,invitation.invitation_url);await credentials(page,'wrong30@e2e.local');await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);expect(new URL(page.url()).searchParams.get('error')).toBe('access_denied');
 expect((await m.organizations.invitations.get(f.org,invitation.id)).id).toBe(invitation.id);
 await page.context().clearCookies();await appFlow(page,invitation.invitation_url);await credentials(page,'right30@e2e.local');expect((await complete(page,await applicationState(page))).claims.org_id).toBe(f.org);
});
test('application entitlement removal blocks code exchange and refresh',async({page})=>{
 const m=await management(),f=await state(),o=m.organizations;
 await m.users.create({connection:'Username-Password-Authentication',email:'entitlement30@e2e.local',password,email_verified:true});
 const invitation=await invite('entitlement30@e2e.local');await o.clients.create(f.org,{clients:[{client_id:'m24-spa',use_for_member_access:true}]});await o.update(f.org,{is_app_entitlement_active:true});
 try {
 await appFlow(page,invitation.invitation_url);await credentials(page,'entitlement30@e2e.local');await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);const flow=await applicationState(page),code=new URL(page.url()).searchParams.get('code');expect(code).toBeTruthy();
 await o.clients.delete(f.org,{clients:['m24-spa']});const rejected=await postToken({grant_type:'authorization_code',client_id:flow.client,redirect_uri:flow.redirect,code,code_verifier:flow.verifier});expect(rejected.status).toBe(400);expect(rejected.body.access_token).toBeUndefined();
 await o.clients.create(f.org,{clients:[{client_id:'m24-spa',use_for_member_access:true}]});await page.context().clearCookies();const next=authorization({connection:'Username-Password-Authentication'});{const url=new URL(next.url);url.searchParams.set('organization',f.org);url.searchParams.set('scope','openid offline_access');next.url=url.href;}await page.goto(next.url);await credentials(page,'entitlement30@e2e.local');const accepted=await complete(page,next);expect(accepted.token.refresh_token).toBeTruthy();
 await o.clients.delete(f.org,{clients:['m24-spa']});const refreshed=await postToken({grant_type:'refresh_token',client_id:'m24-spa',refresh_token:accepted.token.refresh_token});expect(refreshed.status).toBe(400);expect(refreshed.body.access_token).toBeUndefined();
 }finally{await o.update(f.org,{is_app_entitlement_active:false});}
});
test('console administrator attests domain ownership and tenant navigation isolates organization state',async({page})=>{
 test.setTimeout(120000);const f=await state();
 await page.goto(process.env.E2E_M29_SETUP_URL);await page.fill('#password','Plan30-Operator-Password-2026');await page.fill('#password_confirm','Plan30-Operator-Password-2026');await page.click('button[type=submit]');await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto('https://system.e2e.test/admin/');await page.waitForURL(/\/u\/login/);await page.fill('#username','operator@e2e.local');await page.fill('#password','Plan30-Operator-Password-2026');await page.click('button[type=submit]');await page.waitForURL(/\/admin\/t\/.+/);
 await page.goto(`https://system.e2e.test/admin/t/organizations/organizations/${f.org}`);await page.getByRole('tab',{name:'Discovery Domains',exact:true}).click();await page.fill('#organization-domain','console30.e2e.local');await page.getByRole('button',{name:'Add pending domain',exact:true}).click();await expect(page.getByText('Pending — unavailable for discovery',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Attest verified',exact:true}).click();await expect(page.getByRole('dialog')).toContainText('The server does not perform a DNS ownership check');await page.locator('[data-attest]').click();await expect(page.getByText('Verified by administrator attestation',{exact:true})).toBeVisible();
 const domains=await api(`organizations/${f.org}/discovery-domains`);expect(domains.body.domains.find(x=>x.domain==='console30.e2e.local').status).toBe('verified');
 await page.goto('https://system.e2e.test/admin/t/system/organizations');await expect(page.getByRole('heading',{name:'Plan30 Invitations',exact:true})).toHaveCount(0);
 await page.goto(`https://system.e2e.test/admin/t/organizations/organizations/${f.org}`);await page.getByRole('tab',{name:'Discovery Domains',exact:true}).click();await expect(page.getByText('console30.e2e.local',{exact:true})).toBeVisible();
});
test('verified email domain routes login without enrolling an unknown account; pending and disabled domains do not route',async({page})=>{
 const m=await management(),f=await state(),o=m.organizations;
 await m.clients.update('m29-pre',{organization_discovery_methods:['email']});
 // Disable automatic enrollment: domain routing proves no ownership or membership.
 await o.enabledConnections.update(f.org,f.connection,{assign_membership_on_login:false,is_signup_enabled:false});
 const d=await o.discoveryDomains.create(f.org,{domain:'discovery30.e2e.local'});
 async function discover(){const flow=authorization({client:'m29-pre',connection:'Username-Password-Authentication'});await page.goto(flow.url);await page.fill('input[name=email]','unknown@discovery30.e2e.local');await page.click('button[type=submit]');return flow;}
 try{
 await discover();await expect(page.locator('[role=alert]')).toBeVisible();await expect(page.locator('#password')).toHaveCount(0);
 await o.discoveryDomains.update(f.org,d.id,{status:'verified'});await discover();await expect(page.locator('#password')).toBeVisible();
 expect((await api(`organizations/${f.org}/members`)).body.some(x=>x.email==='unknown@discovery30.e2e.local')).toBe(false);
 await o.discoveryDomains.update(f.org,d.id,{use_for_organization_discovery:false});await discover();await expect(page.locator('[role=alert]')).toBeVisible();await expect(page.locator('#password')).toHaveCount(0);
 }finally{await o.discoveryDomains.delete(f.org,d.id);await o.enabledConnections.update(f.org,f.connection,{assign_membership_on_login:true,is_signup_enabled:true});}
});
test('organization password reset preserves organization in actual custom email Action context',async()=>{
 const m=await management(),f=await state();await m.users.create({connection:'Username-Password-Authentication',email:'reset-context30@e2e.local',password,email_verified:true});
 const r=await fixtureFetch('https://sdk.e2e.test/dbconnections/change_password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({client_id:'m24-spa',connection:'Username-Password-Authentication',email:'reset-context30@e2e.local',organization:f.org})});expect(r.status).toBe(200);
 await expect.poll(async()=>(await sink()).filter(x=>x.notification?.message_type==='reset_email'&&x.notification.to==='reset-context30@e2e.local').length,{timeout:30000}).toBe(1);
 const mail=(await sink()).find(x=>x.notification?.message_type==='reset_email'&&x.notification.to==='reset-context30@e2e.local');expect(mail.organization.id).toBe(f.org);expect(mail.organization.name).toBe('plan30-invitations');expect(/\/u\/reset-password\?ticket=/.test(mail.notification.html)).toBe(true);
});
