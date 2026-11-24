// Plan 38a acceptance (make e2e-ad): browser logins through an ad
// connection, answered by the real, pinned AD/LDAP Connector against its own
// mock LDAP server. E2E_M38A_PHASE=first logs in with the directory's
// password; =changed after the SDK changed it through the connector.
import {test,expect} from '@playwright/test';
import {readFile} from 'node:fs/promises';
const work=process.env.E2E_M38A_WORK;
test.skip(!work,'Run make e2e-ad');
test.use({trace:'off'});
const phase=process.env.E2E_M38A_PHASE??'first';
const origin='https://localhost:9565',callback='https://callback.invalid/cb';
const creds=work?JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8')):{};

function authorize(extra={}){
 const q=new URLSearchParams({client_id:'m38a-spa',redirect_uri:callback,response_type:'code',scope:'openid profile email',state:'s-'+Date.now(),
  code_challenge:'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method:'S256',...extra});
 return `${origin}/authorize?${q}`;
}

// login submits username and password and returns the callback URL, or
// null when the login page answers again.
async function login(page,username,password,extra={connection:'corp-ad'}){
 // Route handlers do not see redirect targets, so the callback is caught
 // from the request events (the navigation to callback.invalid then fails).
 let landed=null;
 page.on('request',r=>{if(r.url().startsWith(callback))landed=r.url()});
 await page.goto(authorize(extra));
 await page.locator('input[name="username"]').fill(username);
 await page.locator('input[name="password"]').fill(password);
 await page.locator('button[type="submit"],input[type="submit"]').first().click();
 await Promise.race([page.waitForRequest(r=>r.url().startsWith(callback),{timeout:8000}).catch(()=>{}),page.waitForResponse(r=>r.url().includes('/u/login')&&r.request().method()==='POST'&&r.status()!==302,{timeout:8000}).catch(()=>{})]);
 await page.waitForTimeout(250);
 return landed;
}

test.describe.configure({mode:'serial'});

if(phase==='first'){
 test('wrong directory password is refused by the connector',async({page})=>{
  expect(await login(page,'jdoe','not-the-password')).toBeNull();
  await expect(page.locator('body')).toContainText(/incorrect|wrong/i);
  await expect(page.locator('a[href*="/u/signup"]')).toHaveCount(0);
  await expect(page.locator('a[href*="reset-password"]')).toHaveCount(0);
 });
 test('directory user signs in through the connector',async({page})=>{
  const url=await login(page,'jdoe',creds.directoryPassword);
  expect(url,'reached the application').toBeTruthy();
  expect(new URL(url).searchParams.get('code')).toBeTruthy();
 });
 test('LDAP filter characters in the username are escaped by the connector',async({page,browser})=>{
  const url=await login(page,'jd()e',creds.directoryPassword);
  expect(url,'jd()e signed in').toBeTruthy();
  // A fresh browser: the first one now has a session.
  const fresh=await browser.newContext({ignoreHTTPSErrors:true});
  try{expect(await login(await fresh.newPage(),'*',creds.directoryPassword)).toBeNull()}finally{await fresh.close()}
 });
}else{
 test('the old password no longer works after the change',async({page})=>{
  expect(await login(page,'jdoe',creds.directoryPassword)).toBeNull();
 });
 test('the new password set through the connector signs in',async({page})=>{
  const url=await login(page,'jdoe',creds.newPassword);
  expect(url,'reached the application').toBeTruthy();
 });
}
