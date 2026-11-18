import {test,expect} from '@playwright/test';
import {authorization,complete} from './social/browser.mjs';
import {api,localClaims} from './m39a-apple-client.mjs';
if(process.env.E2E_M39A!=='1')throw new Error('Run make e2e-apple; the Apple lane never silently skips');
test.use({proxy:{server:'http://127.0.0.1:9198'}});

test('cross-site Apple form_post, verified token exchange, repeated login preserves first name',async({page})=>{
 let posts=0;
 for(let i=0;i<2;i++){
  await page.context().clearCookies();
  const flow=authorization({connection:'apple'});await page.goto(flow.url);
  await expect(page).toHaveTitle('Mock Apple sign-in');expect(new URL(page.url()).hostname).toBe('apple.idp.test');
  const q=new URL(page.url()).searchParams;expect(q.get('response_mode')).toBe('form_post');expect(q.has('code_challenge')).toBe(false);expect(q.get('nonce')).toBeTruthy();
  const attempt=(await page.context().cookies('https://sdk.e2e.test/login/callback')).find(c=>c.sameSite==='None');expect(attempt).toBeTruthy();expect(attempt.secure).toBe(true);
  const callbackPromise=page.waitForRequest(r=>new URL(r.url()).pathname==='/login/callback'&&r.method()==='POST');
  await page.fill('#subject','web-name');await page.getByRole('button',{name:'Allow',exact:true}).click();
  const callback=await callbackPromise;posts++;expect((await callback.allHeaders())['sec-fetch-site']).toBe('cross-site');
  const fields=new URLSearchParams(callback.postData());expect(fields.get('code')).toBeTruthy();if(posts===1)expect(fields.get('user')).toContain('firstName');else expect(fields.has('user')).toBe(false);
  const {token}=await complete(page,flow);const claims=await localClaims(token.id_token,'m24-spa');expect(claims.sub).toBe('apple|web-name');
  const u=await api('users/'+encodeURIComponent('apple|web-name'));expect(u.status).toBe(200);expect(u.body.name).toBe('Apple web-name');expect(u.body.given_name).toBe('Apple');expect(u.body.family_name).toBe('web-name');expect(u.body.email).toBe('web-name@apple.e2e.test');expect(u.body.email_verified).toBe(true);
 }
 expect(posts).toBe(2);
});
for(const [subject,email,verified,privateEmail] of [['relay','relay@privaterelay.appleid.com',true,true],['unverified','unverified@apple.e2e.test',false,false],['boolean-verified','boolean-verified@apple.e2e.test',true,false]]){
 test(`Apple browser profile: ${subject}`,async({page})=>{
  const flow=authorization({connection:'apple'});await page.goto(flow.url);await expect(page).toHaveTitle('Mock Apple sign-in');await page.fill('#subject',subject);await page.getByRole('button',{name:'Allow',exact:true}).click();await complete(page,flow);
  const u=await api('users/'+encodeURIComponent('apple|'+subject));expect(u.status).toBe(200);expect(u.body.email).toBe(email);expect(u.body.email_verified).toBe(verified);expect(u.body.identities[0].profileData.is_private_email).toBe(String(privateEmail));expect(u.body.identities[0].isSocial).toBe(true);
 });
}
