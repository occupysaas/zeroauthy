import {test,expect} from '@playwright/test';
import {appendFile,readFile} from 'node:fs/promises';
import {state,saveState,work,password,operatorPassword,email,marker,noSecrets,fixedCode,api,until} from './m31-node-auth0.mjs';
import {startTail} from './m31-logs-cli.mjs';
import {authorization,complete} from './social/browser.mjs';
test.skip(!process.env.E2E_M31_WORK,'Run make e2e-logs');
test.use({proxy:{server:'http://127.0.0.1:9198'},trace:'off'});
test('Action deny → Logs Live failure → masked execution → console redeploy → successful retry',async({browser})=>{
 test.setTimeout(150000);const f=await state();
 const operator=await browser.newContext({proxy:{server:'http://127.0.0.1:9198'},ignoreHTTPSErrors:true});const customer=await browser.newContext({proxy:{server:'http://127.0.0.1:9198'},ignoreHTTPSErrors:true});
 await customer.route(/^https:\/\/callback\.e2e\.test\//,route=>route.fulfill({status:200,contentType:'text/html',body:'<!doctype html><title>Plan31 local callback</title>'}));
 const pending=[];let monitorIndex=0;
 const listen=page=>{
  page.on('response',response=>{const path=new URL(response.url()).pathname;if(!(/\/(?:logs(?:\/|$)|stats(?:\/|$)|actions\/executions(?:\/|$)|executions(?:\/|$)|log-streams\/status)/.test(path)))return;
   pending.push((async()=>{const body=await response.text();noSecrets(body,'browser monitoring response');await appendFile(`${work}/browser-monitoring.jsonl`,JSON.stringify({n:++monitorIndex,url:response.url(),status:response.status(),body})+'\n');})());});
  page.on('console',msg=>pending.push(appendFile(`${work}/browser-console.jsonl`,JSON.stringify({type:msg.type(),text:msg.text()})+'\n')));
 };
 const consolePage=await operator.newPage(),loginPage=await customer.newPage();listen(consolePage);listen(loginPage);let tail,tailFailure;
 try{
  const setup=(await readFile(`${work}/operator-setup.txt`,'utf8')).trim().split('\n').at(-1);
  await consolePage.goto(setup);await consolePage.fill('#password',operatorPassword);await consolePage.fill('#password_confirm',operatorPassword);await consolePage.click('button[type=submit]');await expect(consolePage.locator('h1')).toHaveText('Password changed');
  await consolePage.goto('https://system.e2e.test/admin/');await consolePage.waitForURL(/\/u\/login/);await consolePage.fill('#username','operator31@e2e.local');await consolePage.fill('#password',operatorPassword);await consolePage.click('button[type=submit]');await consolePage.waitForURL(/\/admin\/t\/.+/);
  await consolePage.goto('https://system.e2e.test/admin/t/logs/logs');await expect(consolePage.locator('#logs-live')).toBeEnabled();await consolePage.locator('#logs-live').check();tail=await startTail();
  const flow=authorization({client:'m31-spa',connection:'Username-Password-Authentication'});await loginPage.goto(flow.url);await loginPage.fill('#username',email);await loginPage.fill('#password',password);await loginPage.click('button[type=submit]');await loginPage.waitForURL(/^https:\/\/callback\.e2e\.test\//);expect(new URL(loginPage.url()).searchParams.get('error')).toBe('access_denied');expect(new URL(loginPage.url()).searchParams.get('error_description')).toContain('Plan31 troubleshooting denied');
  const row=consolePage.getByTestId('log-row').filter({has:consolePage.locator('code',{hasText:/^f$/})}).filter({hasText:'Plan31 troubleshooting denied'});await expect(row).toHaveCount(1,{timeout:30000});
  const href=await row.locator('a').first().getAttribute('href');f.failure=href.split('/').at(-1);expect(f.failure).toMatch(/^\d{56}$/);try{await tail.contains(f.failure);}catch(e){tailFailure=e.message;}
  await row.locator('a').first().click();const dialog=consolePage.getByRole('dialog');await expect(dialog).toContainText('Plan31 troubleshooting denied');const execution=dialog.getByRole('link').filter({hasText:/execution exe_/i});await expect(execution).toHaveCount(1);f.execution=(await execution.getAttribute('href')).split('/').at(-1);
  await execution.click();await expect(consolePage.locator('body')).toContainText('plan31-action-console');await expect(consolePage.locator('body')).toContainText(marker);await expect(consolePage.locator('body')).toContainText('Plan31 Troubleshooting');noSecrets(await consolePage.locator('body').innerText(),'execution UI');await expect.soft(consolePage.locator('body'),'execution displays the explicit Action denial reason').toContainText('Plan31 troubleshooting denied');
  // The repair and redeploy happen through the real operator editor/session.
  await consolePage.getByRole('link',{name:'Plan31 Troubleshooting',exact:true}).click();await consolePage.fill('#action-code',fixedCode);await consolePage.getByRole('button',{name:'Save draft',exact:true}).click();await expect(consolePage.getByRole('button',{name:'Deploy',exact:true})).toBeEnabled({timeout:30000});await consolePage.getByRole('button',{name:'Deploy',exact:true}).click();await expect(consolePage.locator('body')).toContainText('Draft deployed.');
  await consolePage.goto('https://system.e2e.test/admin/t/logs/logs');await expect(consolePage.locator('#logs-live')).toBeEnabled();await consolePage.locator('#logs-live').check();
  await customer.clearCookies();const retry=authorization({client:'m31-spa',connection:'Username-Password-Authentication'});await loginPage.goto(retry.url);await loginPage.fill('#username',email);await loginPage.fill('#password',password);await loginPage.click('button[type=submit]');
  // The callback is a local intercepted document; token issuance is real PKCE.
  const result=await complete(loginPage,retry);expect(result.claims['https://plan31.test/fixed']).toBe(true);
  const success=consolePage.getByTestId('log-row').filter({has:consolePage.locator('code',{hasText:/^s$/})}).filter({hasText:email});await expect(success).toHaveCount(1,{timeout:30000});f.success=(await success.locator('a').first().getAttribute('href')).split('/').at(-1);
  await success.locator('a').first().click();await expect(consolePage.getByRole('dialog').getByRole('link').filter({hasText:/execution exe_/i})).toHaveCount(1);
  const saved=await api(`logs/${f.failure}`);expect(saved.details.actions.executions).toContain(f.execution);await saveState(f);await until(()=>monitorIndex>=3,'browser response capture');if(tailFailure)throw Error(tailFailure);
 }finally{if(tail)await tail.close();await operator.close();await customer.close();await Promise.all(pending);}
});
