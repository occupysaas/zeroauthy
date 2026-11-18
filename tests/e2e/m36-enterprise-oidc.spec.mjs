import {test,expect} from '@playwright/test';
import {createHash,randomBytes}from 'node:crypto';
import {readFile}from 'node:fs/promises';
test.use({proxy:{server:'http://127.0.0.1:9198'}});
function authorize(extra={}){const verifier=randomBytes(32).toString('base64url');return `https://sdk.e2e.test/authorize?${new URLSearchParams({client_id:'m24-spa',redirect_uri:'https://callback.e2e.test/',response_type:'code',scope:'openid profile email',state:'app-state',nonce:'app-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',...extra})}`;}
for(const [connection,subject]of [['enterprise-front','front-user'],['enterprise-private','private-user'],['enterprise-okta','okta-user']]){
 test(`${connection}: provider login completes`,async({page})=>{let posted=false;page.on('request',r=>{if(r.url().includes('/login/callback')&&r.method()==='POST')posted=true;});await page.goto(authorize({connection}));await expect(page).toHaveTitle('Mock enterprise sign-in',{timeout:20000});await page.fill('#subject',subject);await page.getByRole('button',{name:'Allow',exact:true}).click();await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);expect(new URL(page.url()).searchParams.get('code')).toBeTruthy();expect(posted).toBe(connection==='enterprise-front');});
}
test('identifier-first routes the corporate domain without the password page',async({page})=>{await page.goto(authorize());await expect(page.locator('#password')).toHaveCount(0);await page.locator('input[name="username"]').fill('user@corp.example');await page.getByRole('button',{name:'Continue',exact:true}).click();await expect(page).toHaveTitle('Mock enterprise sign-in',{timeout:20000});await page.fill('#subject','private-user');await page.getByRole('button',{name:'Allow',exact:true}).click();await page.waitForURL(/^https:\/\/callback\.e2e\.test\/\?/);});
test('mapped profile and enterprise keys are visible in the operator console',async({page})=>{
 const setup=(await readFile(process.env.E2E_SETUP_FILE,'utf8')).trim();
 await page.goto(setup);
 await page.locator('input[name="password"]').fill('Operator-Enterprise-2026!');
 const confirm=page.locator('input[name="password_confirm"]');if(await confirm.count())await confirm.fill('Operator-Enterprise-2026!');
 await page.locator('form').evaluate(form=>form.requestSubmit());
 await expect(page.locator('h1')).toHaveText('Password changed');
 await page.goto('https://system.e2e.test/admin/');
 const email=page.locator('input[name="username"]');if(await email.count()){await email.fill('operator@e2e.local');await page.locator('input[name="password"]').fill('Operator-Enterprise-2026!');await page.locator('form').evaluate(form=>form.requestSubmit());}
 await page.waitForURL(/\/admin\//);
 const ids=JSON.parse(await readFile(`${process.env.E2E_M36_WORK}/connections.json`,'utf8'));
 await page.goto(`https://system.e2e.test/admin/t/social/enterprise/${ids.back}`);
 await expect(page.getByRole('tab',{name:'Mapping',exact:true})).toBeVisible();
 await page.getByRole('tab',{name:'Mapping',exact:true}).click();await expect(page.locator('#enterprise-mapping')).toHaveValue(/federated_groups/);
 await page.getByRole('tab',{name:'Keys',exact:true}).click();await expect(page.getByText('Register a public certificate',{exact:false})).toBeVisible();
});
