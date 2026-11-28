import {test,expect} from '@playwright/test';
import {readFile,writeFile} from 'node:fs/promises';
import {management,bind,deploy} from './m27-node-auth0.mjs';
import {audience,email,password,decode} from './rbac/client.mjs';
import {authorization,complete} from './social/browser.mjs';
const fixture=async()=>JSON.parse(await readFile(process.env.E2E_M27_STATE,'utf8'));
test.skip(!process.env.E2E_M27,'Run make e2e-actions');
test.use({proxy:{server:'http://127.0.0.1:9198'}});
async function login(page){const f=authorization({connection:'Username-Password-Authentication',audience});await page.goto(f.url);await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');return f;}

test('auth0-spa-js reads namespaced ID/access claims and roles from actual PKCE tokens',async({page})=>{
 const m=await management(),f=await fixture();await bind(m,[f.claims]);
 await page.goto('https://callback.e2e.test/spa');await page.waitForFunction(()=>window.ready);await page.click('#login');await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');
 await page.waitForFunction(()=>window.claims||window.failure);expect(await page.evaluate(()=>window.failure)).toBeUndefined();
 expect(await page.evaluate(()=>window.claims['https://actions.test/id'])).toBe('browser');expect(await page.evaluate(()=>window.claims['https://actions.test/roles'])).toEqual([f.role.name]);
 expect(decode(await page.evaluate(()=>window.access))['https://actions.test/access']).toBe('browser');
});
test('Action denial renders on the hosted error page',async({page})=>{
 const m=await management(),f=await fixture();await bind(m,[f.deny]);await login(page);await expect(page.locator('body')).toContainText('Plan27 blocked by Action');
});
test('throwing Action renders a persisted execution readable through node-auth0',async({page})=>{
 const m=await management(),f=await fixture();const failure=await deploy(m,'Browser Failure',`exports.onExecutePostLogin=async()=>{throw Error('fixture failure');};`);await bind(m,[failure]);await login(page);
 await expect(page.locator('body')).toContainText('exe_');const id=(await page.locator('body').innerText()).match(/exe_[A-Za-z0-9_-]+/)[0];expect((await m.actions.executions.get(id)).id).toBe(id);f.execution=id;await writeFile(process.env.E2E_M27_STATE,JSON.stringify(f),{mode:0o600});
});
test('redirect fixture adds a=1 and POSTs state-bound encodeToken token to continue',async({page})=>{
 const m=await management(),f=await fixture();await bind(m,[f.redirect]);
 const flow=await login(page);await page.waitForURL('https://callback.e2e.test/redirect**');await page.getByRole('button',{name:'Continue',exact:true}).click();const result=await complete(page,flow);expect(result.claims['https://actions.test/redirect']).toBe(true);
});
test('console creates edits builds deploys binds and tests an Action',async({page})=>{
 test.setTimeout(120_000);await page.goto(process.env.E2E_M26_SETUP_URL);await page.fill('#password','Plan27-Operator-Password-2026');await page.fill('#password_confirm','Plan27-Operator-Password-2026');await page.click('button[type=submit]');await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto('https://system.e2e.test/admin/');await page.waitForURL(/\/u\/login/);await page.fill('#username','operator@e2e.local');await page.fill('#password','Plan27-Operator-Password-2026');await page.click('button[type=submit]');await page.waitForURL(/\/admin\/t\/.+/);
 await page.goto('https://system.e2e.test/admin/t/rbac/actions');await page.getByRole('button',{name:'Create Action',exact:true}).click();await page.fill('#action-name','Console Action');await page.selectOption('#action-trigger','post-login');await page.getByRole('dialog').getByRole('button',{name:'Create Action',exact:true}).click();
 await page.fill('#action-code',`exports.onExecutePostLogin=async(e,a)=>{console.log('console test log');a.idToken.setCustomClaim('https://actions.test/console',true);};`);await page.getByRole('button',{name:'Save draft',exact:true}).click();await expect(page.getByRole('button',{name:'Deploy',exact:true})).toBeEnabled({timeout:30000});await page.getByRole('button',{name:'Deploy',exact:true}).click();await expect(page.locator('body')).toContainText('Draft deployed.');
 const id=page.url().split('/').at(-1);await page.goto(`https://system.e2e.test/admin/t/rbac/actions/${id}/test`);await page.getByRole('button',{name:'Run test',exact:true}).click();await expect(page.locator('body')).toContainText('console test log');
 await page.goto('https://system.e2e.test/admin/t/rbac/actions/triggers/post-login');await page.selectOption('#binding-action',{label:'Console Action'});await page.getByRole('button',{name:'Add binding',exact:true}).click();await page.getByRole('button',{name:'Save bindings',exact:true}).click();await expect(page.locator('body')).toContainText('Trigger bindings saved.');
 for(const width of [390,1280]){await page.setViewportSize({width,height:900});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);}
 const m=await management(),bindings=(await m.actions.triggers.bindings.list('post-login')).data;expect(bindings.some(b=>b.action.name==='Console Action')).toBe(true);
});

test('Actions III revokes a browser session before issuing tokens',async({page})=>{
 const m=await management();const action=await deploy(m,'Session revoke 40',`exports.onExecutePostLogin=(event,api)=>api.session.revoke('Plan40 session refused');`);await bind(m,[action]);
 await login(page);await expect(page.locator('body')).toContainText('Plan40 session refused');
 expect((await page.context().cookies()).filter(c=>c.name==='za_session')).toHaveLength(0);
 await bind(m,[]);
});
test('Actions III shortens the session and its persistent cookie',async({page})=>{
 const m=await management();const action=await deploy(m,'Session expiry 40',`exports.onExecutePostLogin=(event,api)=>{api.session.setExpiresAt(Date.now()+300000);api.idToken.setCustomClaim('https://actions.test/session',event.session.id);};`);await bind(m,[action]);
 const start=Date.now()/1000;const result=await complete(page,await login(page));
 expect(result.claims['https://actions.test/session']).toBeTruthy();
 const cookie=(await page.context().cookies()).find(c=>c.name==='za_session');expect(cookie).toBeTruthy();expect(cookie.expires).toBeGreaterThan(start);expect(cookie.expires).toBeLessThanOrEqual(start+305);
 await bind(m,[]);
});
test('Actions III custom ID-token claims reach userinfo for the SPA session',async({page})=>{
 const m=await management(),f=await fixture();await bind(m,[f.claims]);
 await page.goto('https://callback.e2e.test/spa');await page.waitForFunction(()=>window.ready);await page.click('#login');await page.fill('#username',email);await page.fill('#password',password);await page.click('button[type=submit]');
 await page.waitForFunction(()=>window.claims||window.failure);expect(await page.evaluate(()=>window.failure)).toBeUndefined();
 expect(await page.evaluate(()=>window.claims['https://actions.test/id'])).toBe('browser');
 const user=await page.evaluate(async()=>{const response=await fetch('https://sdk.e2e.test/userinfo',{headers:{authorization:'Bearer '+window.access}});return {status:response.status,body:await response.json()};});
 expect(user.status).toBe(200);expect(user.body['https://actions.test/id']).toBe('browser');expect(user.body.sub).toBe(await page.evaluate(()=>window.claims.sub));
});
test('Actions III links a federated login into a database primary',async({page})=>{
 const m=await management(),f=await fixture();
 const connection=await m.connections.create({name:'plan40-social',strategy:'oidc',enabled_clients:['m24-spa'],options:{type:'back_channel',client_id:'m24-upstream-client',client_secret:'m24-upstream-secret-not-for-production',discovery_url:'https://idp.e2e.test/oidc/.well-known/openid-configuration',scopes:'openid email'}});
 const action=await deploy(m,'Primary user 40',`exports.onExecutePostLogin=(event,api)=>{if(event.connection.name==='plan40-social')api.authentication.setPrimaryUser(${JSON.stringify(f.user.user_id)});};`);await bind(m,[action]);
 const flow=authorization({connection:connection.name,audience});await page.goto(flow.url);await page.fill('#subject','plan40-secondary');await page.getByRole('button',{name:'Allow',exact:true}).click();
 const result=await complete(page,flow);expect(result.claims.sub).toBe(f.user.user_id);
 const primary=await m.users.get(f.user.user_id);expect(primary.identities.some(i=>i.connection===connection.name)).toBe(true);
 await bind(m,[]);
});
