// Plans 39b and 39d: every live Tier 1 and Tier 2 descriptor strategy through a browser login with
// an actual code exchange against its local stand-in (provider /social).
import {test,expect} from '@playwright/test';
import {authorization,complete} from './social/browser.mjs';
import {api,upstream} from './social/client.mjs';
if(process.env.E2E_M39B!=='1')throw new Error('Run make e2e-social-providers; the lane never silently skips');
test.use({proxy:{server:'http://127.0.0.1:9198'}});
test.describe.configure({mode:'serial'});

// strategy → extra options, the effective scope sent upstream and whether
// the email is verified (null: no email). LR39b-4.
const cases=[
 ['facebook',{email:true},'public_profile,email',true],
 ['linkedin',{email:true},'openid profile email',true],
 ['twitter',{},'tweet.read users.read',null],
 ['amazon',{postal_code:true},'profile postal_code',false],
 ['paypal',{email:true},'openid email',true],
 ['paypal-sandbox',{email:true},'openid email',true],
 ['salesforce',{},'id profile',true],
 ['salesforce-sandbox',{},'id profile',true],
 ['salesforce-community',{community_base_url:'https://community.example'},'id profile',true],
 ['yahoo',{},'openid profile email',true],
 ['line',{email:true},'openid profile email',false],
 ['dropbox',{},'account_info.read',true],
 ['box',{},null,false],
 ['bitbucket',{},'account email',true],
 ['shopify',{},null,false],
 // Tier 2 (Plan 39d). redirect is the provider's redirect parameter name.
 ['baidu',{},'basic',null],
 ['bitly',{},null,true],
 ['daccount',{},'openid',null],
 ['dwolla',{},'AccountInfoFull',null],
 ['exact',{baseUrl:'https://start.exactonline.nl'},null,false],
 ['planningcenter',{},'people',null],
 ['soundcloud',{},null,null],
 ['thirtysevensignals',{},null,false],
 ['untappd',{},null,false,'redirect_url'],
 ['vkontakte',{},null,false],
 ['weibo',{},null,null],
 ['wordpress',{},'auth',true],
 ['yandex',{},null,false],
 ['evernote',{},null,null,'oauth1'],
 ['evernote-sandbox',{},null,null,'oauth1'],
];

for(const [strategy,extra,scope,verified,redirect='redirect_uri'] of cases){
 test(`${strategy}: create, sign in, identity ${strategy}|<id>`,async({page})=>{
  const name=`soc-${strategy}`;
  const created=await api('connections','POST',{name,strategy,enabled_clients:['m24-spa'],options:{client_id:upstream.id,client_secret:upstream.secret,...extra}});
  expect(created.status,JSON.stringify(created.body)).toBe(201);
  expect(JSON.stringify(created.body)).not.toContain(upstream.secret);
  await page.context().clearCookies();
  const flow=authorization({connection:name});
  const u=new URL(flow.url);
  if(strategy==='shopify')u.searchParams.set('login_hint','my-shop');
  await page.goto(u.toString());
  const up=new URL(page.url());
  expect(up.origin).toBe('https://idp.e2e.test');
  expect(up.pathname.startsWith(`/social/${strategy}/`)).toBe(true);
  if(redirect!=='oauth1')expect(up.searchParams.get(redirect)).toBe('https://sdk.e2e.test/login/callback');
  else expect(up.searchParams.get('oauth_token')).toBeTruthy();
  expect(up.searchParams.get('scope')).toBe(scope);
  expect(up.searchParams.has('nonce')).toBe(false);
  const sub=`acct-${strategy}`;
  await page.fill('#subject',sub);
  await page.getByRole('button',{name:'Allow',exact:true}).click();
  const {claims}=await complete(page,flow);
  expect(claims.sub).toBe(`${strategy}|${sub}`);
  const user=await api('users/'+encodeURIComponent(`${strategy}|${sub}`));
  expect(user.status).toBe(200);
  expect(user.body.identities[0]).toMatchObject({provider:strategy,connection:name,user_id:sub,isSocial:true});
  if(verified===null)expect(user.body.email).toBeUndefined();
  else expect(user.body).toMatchObject({email:`${sub}@${strategy}.e2e.test`,email_verified:verified});
 });
}

test('a denied upstream consent ends the login without a user',async({page})=>{
 await page.context().clearCookies();
 const flow=authorization({connection:'soc-amazon'});
 await page.goto(flow.url);
 await page.fill('#subject','denied-user');
 const callback=page.waitForResponse(r=>{const u=new URL(r.url());return u.hostname==='sdk.e2e.test'&&u.pathname==='/login/callback';});
 await page.getByRole('button',{name:'Deny',exact:true}).click();
 await callback;
 expect(page.url()).not.toContain('callback.e2e.test');
 expect((await api('users/'+encodeURIComponent('amazon|denied-user'))).status).toBe(404);
});

test('retired Fitbit and Instagram are stored but sign-in is refused before any upstream call',async({page})=>{
 for(const strategy of ['fitbit','instagram']){
  const created=await api('connections','POST',{name:`soc-${strategy}`,strategy,enabled_clients:['m24-spa'],options:{client_id:upstream.id,client_secret:upstream.secret}});
  expect(created.status,JSON.stringify(created.body)).toBe(201);
  await page.context().clearCookies();
  await page.goto(authorization({connection:`soc-${strategy}`}).url);
  expect(new URL(page.url()).hostname).not.toBe('idp.e2e.test');
 }
});

test('Shopify without a shop in login_hint is refused before any upstream call',async({page})=>{
 await page.context().clearCookies();
 await page.goto(authorization({connection:'soc-shopify'}).url);
 expect(new URL(page.url()).hostname).not.toBe('idp.e2e.test');
});
