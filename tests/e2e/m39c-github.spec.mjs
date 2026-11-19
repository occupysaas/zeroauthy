// Plan 39c, spec §9 G4: the GitHub social connection through browser logins
// with actual code exchanges against the local GitHub-shaped upstream.
import {test,expect} from '@playwright/test';
import {Agent} from 'undici';
import {authorization,complete} from './social/browser.mjs';
import {READER,api,token,fixtureFetch,upstream} from './social/client.mjs';
if(process.env.E2E_M39C!=='1')throw new Error('Run make e2e-github; the GitHub lane never silently skips');
test.use({proxy:{server:'http://127.0.0.1:9198'}});
test.describe.configure({mode:'serial'});

const emailRequired='Your GitHub account needs a verified primary email address to sign in.';
const providerFailed='We could not sign you in with that provider.';
const big='9007199254740993'; // above 2⁵³: must round-trip exactly
const user=id=>api('users/'+encodeURIComponent(id));
const idpTokens=async()=>token(READER,'read:users read:user_idp_tokens');

async function account(id,login,email,mode='verified'){
 const r=await fetch('http://127.0.0.1:9173/github/account',{dispatcher:new Agent(),method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ID:id,Login:login,Email:email,Mode:mode})});
 expect(r.status).toBe(204);
}
// signIn starts a GitHub login on domain, checks the upstream request, signs
// in as account id and returns the flow and zeroauthy's callback response.
async function signIn(page,id,{domain='sdk.e2e.test',button}={}){
 await page.context().clearCookies();
 const flow=authorization({domain,connection:'github'});
 if(button){
  const u=new URL(flow.url);u.searchParams.delete('connection');
  await page.goto(u.toString());await page.getByRole('button',{name:button,exact:true}).click();
 }else await page.goto(flow.url);
 await expect(page).toHaveTitle('Mock GitHub sign-in');
 const up=new URL(page.url());
 expect(up.origin+up.pathname).toBe('https://idp.e2e.test/github/login/oauth/authorize');
 expect(up.searchParams.get('redirect_uri')).toBe(`https://${domain}/login/callback`);
 expect(up.searchParams.get('code_challenge_method')).toBe('S256');
 expect(up.searchParams.get('scope')).toBe('user:email read:user');
 expect(up.searchParams.has('nonce')).toBe(false);
 await page.fill('#subject',id);
 const callback=page.waitForResponse(r=>{const u=new URL(r.url());return u.hostname===domain&&u.pathname==='/login/callback';});
 await page.getByRole('button',{name:'Allow',exact:true}).click();
 return {flow,callback:await callback};
}
async function refused(page,callback,status,text){
 expect(callback.status()).toBe(status);
 await expect(page.locator('body')).toContainText(text);
 expect(page.url()).not.toContain('callback.e2e.test');
}
async function importUsers(users){
 const db=(await api('connections')).body.find(c=>c.name==='Username-Password-Authentication');
 const fd=new FormData();
 fd.set('users',new Blob([JSON.stringify(users)],{type:'application/json'}),'users.json');fd.set('connection_id',db.id);fd.set('send_completion_email','false');
 const r=await fixtureFetch('https://sdk.e2e.test/api/v2/jobs/users-imports',{method:'POST',headers:{authorization:`Bearer ${await token()}`},body:fd});
 const job=await r.json();expect(r.status,JSON.stringify(job)).toBe(202);
 for(let i=0;i<200;i++){
  const j=(await api(`jobs/${job.id}`)).body;
  if(j.status!=='pending'&&j.status!=='processing'){expect(j.status,JSON.stringify(j)).toBe('completed');expect(j.summary.inserted,JSON.stringify(j)).toBe(users.length);return;}
  await new Promise(res=>setTimeout(res,100));
 }
 throw new Error('import job did not finish');
}

test('Management API: create returns the effective scope; PATCH replaces flags',async()=>{
 const created=await api('connections','POST',{name:'github',strategy:'github',enabled_clients:['m24-spa'],options:{client_id:upstream.id,client_secret:upstream.secret,read_user:true,repo:true}});
 expect(created.status,JSON.stringify(created.body)).toBe(201);
 expect(JSON.stringify(created.body)).not.toContain(upstream.secret);expect(created.body.options.client_secret).toBeUndefined();
 expect(created.body.options.scope).toEqual(['user:email','read:user','repo']);
 // Unchecking repo: options are sent whole without it, and the effective
 // scope is replaced, not merged.
 const patched=await api(`connections/${created.body.id}`,'PATCH',{options:{client_id:upstream.id,read_user:true}});
 expect(patched.status,JSON.stringify(patched.body)).toBe(200);
 expect(patched.body.options.scope).toEqual(['user:email','read:user']);expect(patched.body.options.scope).not.toContain('repo');
 expect(patched.body.options.repo??false).toBe(false);
 const mismatch=await api(`connections/${created.body.id}`,'PATCH',{options:{client_id:upstream.id,read_user:true,scope:['user:email']}});
 expect(mismatch.status).toBe(400);expect(mismatch.body.message).toContain('options.scope must match the scope flags (user:email read:user)');
 expect((await api(`connections/${created.body.id}`)).body.options.scope).toEqual(['user:email','read:user']);
});

test('first login creates github|<id>; a renamed login updates nickname on repeat login',async({page})=>{
 await account(big,'octo','octo@github.e2e.test');
 let {flow}=await signIn(page,big);
 expect((await complete(page,flow)).claims.sub).toBe('github|'+big);
 const first=await user('github|'+big);
 expect(first.status).toBe(200);
 expect(first.body).toMatchObject({user_id:'github|'+big,nickname:'octo',email:'octo@github.e2e.test',email_verified:true});
 expect(first.body.identities).toHaveLength(1);
 expect(first.body.identities[0]).toMatchObject({provider:'github',connection:'github',user_id:big,isSocial:true});
 expect(first.body.identities[0].access_token).toBeUndefined();
 await account(big,'octo','octo@github.e2e.test','rename');
 ({flow}=await signIn(page,big));
 expect((await complete(page,flow)).claims.sub).toBe('github|'+big);
 const again=await user('github|'+big);
 expect(again.body).toMatchObject({user_id:'github|'+big,nickname:'octo-renamed',created_at:first.body.created_at});
 expect(again.body.logins_count).toBe(2);
});

test('hosted login page: Continue with GitHub',async({page})=>{
 await account('1001','mona','mona@github.e2e.test');
 const {flow}=await signIn(page,'1001',{button:'Continue with GitHub'});
 expect((await complete(page,flow)).claims.sub).toBe('github|1001');
});

test('a second GitHub account with the same email is a separate user',async({page})=>{
 for(const [id,login] of [['2001','twin-a'],['2002','twin-b']]){
  await account(id,login,'twin@github.e2e.test');
  const {flow}=await signIn(page,id);
  expect((await complete(page,flow)).claims.sub).toBe('github|'+id);
 }
 const a=await user('github|2001'),b=await user('github|2002');
 expect(a.body.email).toBe('twin@github.e2e.test');expect(b.body.email).toBe('twin@github.e2e.test');
 expect(a.body.identities).toHaveLength(1);expect(b.body.identities).toHaveLength(1);
});

test('an imported github identity logs in to the imported account',async({page})=>{
 await importUsers([{email:'imported@github.e2e.test',email_verified:true,user_id:'gh-imported',identities:[{provider:'github',connection:'github',user_id:'3001'}]}]);
 await account('3001','imported','imported@github.e2e.test');
 const {flow}=await signIn(page,'3001');
 expect((await complete(page,flow)).claims.sub).toBe('auth0|gh-imported');
 expect((await user('github|3001')).status).toBe(404);
 const imported=await user('auth0|gh-imported');
 expect(imported.body.identities.map(i=>`${i.provider}|${i.user_id}`)).toEqual(['auth0|gh-imported','github|3001']);
 expect(imported.body.logins_count).toBe(1);
});

for(const [mode,first,repeat] of [['unverified','4001','4101'],['no-scope-403','4002','4102']]){
 test(`${mode}: email-required page on first and on repeat login`,async({page})=>{
  await account(first,'new-'+mode,`new-${mode}@github.e2e.test`,mode);
  let {callback}=await signIn(page,first);
  await refused(page,callback,403,emailRequired);
  expect((await user('github|'+first)).status).toBe(404);
  await account(repeat,'old-'+mode,`old-${mode}@github.e2e.test`);
  const {flow}=await signIn(page,repeat);await complete(page,flow);
  const before=await user('github|'+repeat);expect(before.status).toBe(200);
  await account(repeat,'old-'+mode,`old-${mode}@github.e2e.test`,mode);
  ({callback}=await signIn(page,repeat));
  await refused(page,callback,403,emailRequired);
  expect((await user('github|'+repeat)).body).toEqual(before.body);
 });
}

test('rate-limited address lookup shows the provider-failure page',async({page})=>{
 await account('5001','limited','limited@github.e2e.test','rate-limited');
 const {callback}=await signIn(page,'5001');
 await refused(page,callback,502,providerFailed);
 await expect(page.locator('body')).not.toContainText(emailRequired);
 expect((await user('github|5001')).status).toBe(404);
});

test('upstream token only with read:user_idp_tokens, never to another tenant',async()=>{
 const id=encodeURIComponent('github|'+big);
 const scoped=await api(`users/${id}`,'GET',undefined,await idpTokens());
 expect(scoped.status).toBe(200);expect(scoped.headers.get('cache-control')).toBe('no-store');
 expect(scoped.body.identities[0].access_token).toMatch(/^gho_/);
 expect(scoped.body.identities[0].refresh_token).toBeUndefined(); // non-expiring OAuth app token
 for(const bearer of [await token(READER,'read:users'),await token()]){
  const plain=await api(`users/${id}`,'GET',undefined,bearer);
  expect(plain.status).toBe(200);expect(JSON.stringify(plain.body)).not.toContain('access_token');
 }
 const otherToken=async audience=>fixtureFetch('https://other.e2e.test/oauth/token',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({grant_type:'client_credentials',client_id:'other-reader',client_secret:'other-reader-secret-not-for-production',audience,scope:'read:users read:user_idp_tokens'})});
 const own=await otherToken('https://other.e2e.test/api/v2/');const ownBody=await own.json();expect(own.status,JSON.stringify(ownBody)).toBe(200);
 const cross=await fixtureFetch(`https://sdk.e2e.test/api/v2/users/${id}`,{headers:{authorization:`Bearer ${ownBody.access_token}`}});
 const crossText=await cross.text();expect(cross.status).toBe(401);expect(crossText).not.toContain('access_token');expect(crossText).not.toContain('gho_');
 const foreignAudience=await otherToken('https://sdk.e2e.test/api/v2/');
 expect(foreignAudience.status).not.toBe(200);expect(await foreignAudience.text()).not.toContain('access_token');
});

test('upstream token is no longer returned after unlink or user deletion',async({page})=>{
 await account('6001','linker','linker@github.e2e.test');
 const {flow}=await signIn(page,'6001');await complete(page,flow);
 expect((await api('users/github%7C6001','GET',undefined,await idpTokens())).body.identities[0].access_token).toMatch(/^gho_/);
 const primary=await api('users','POST',{connection:'Username-Password-Authentication',email:'primary-6001@e2e.test',password:'Primary-Password-2026!'});
 expect(primary.status,JSON.stringify(primary.body)).toBe(201);
 const pid=encodeURIComponent(primary.body.user_id);
 const linked=await api(`users/${pid}/identities`,'POST',{provider:'github',user_id:'6001'});
 expect(linked.status,JSON.stringify(linked.body)).toBe(201);
 const withLink=await api(`users/${pid}`,'GET',undefined,await idpTokens());
 expect(withLink.body.identities.find(i=>i.provider==='github').access_token).toMatch(/^gho_/);
 const unlinked=await api(`users/${pid}/identities/github/6001`,'DELETE');
 expect(unlinked.status,JSON.stringify(unlinked.body)).toBe(200);
 const afterUnlink=await api(`users/${pid}`,'GET',undefined,await idpTokens());
 expect(afterUnlink.body.identities).toHaveLength(1);expect(JSON.stringify(afterUnlink.body)).not.toContain('access_token');
 // Deleting the user drops its token record: the same GitHub identity,
 // imported again, has no token until it logs in.
 expect((await api('users/github%7C6001','DELETE')).status).toBe(204);
 expect((await user('github|6001')).status).toBe(404);
 await importUsers([{email:'reimported@github.e2e.test',user_id:'gh-reimported',identities:[{provider:'github',connection:'github',user_id:'6001'}]}]);
 const reimported=await api('users/auth0%7Cgh-reimported','GET',undefined,await idpTokens());
 expect(reimported.status).toBe(200);expect(reimported.body.identities).toHaveLength(2);expect(JSON.stringify(reimported.body)).not.toContain('access_token');
});

test('two origins each return to their own callback',async({page})=>{
 await account('7001','origins','origins@github.e2e.test');
 for(const domain of ['alt.e2e.test','sdk.e2e.test']){
  const {flow,callback}=await signIn(page,'7001',{domain});
  expect(new URL(callback.url()).origin).toBe(`https://${domain}`);
  const {claims}=await complete(page,flow);
  expect(claims.sub).toBe('github|7001');expect(claims.iss).toBe(`https://${domain}/`);
 }
});
