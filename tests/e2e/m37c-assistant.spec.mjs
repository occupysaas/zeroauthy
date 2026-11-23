// Plan 37c Phase B acceptance: the pinned node-auth0 SDK issues an SSO
// ticket; a real browser runs the self-service assistant as the customer
// administrator against a samlify identity provider. Run through
// make e2e-self-service.
import {test,expect} from '@playwright/test';
import {once} from 'node:events';
import {randomUUID} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
import https from 'node:https';
import express from 'express';
import {rateLimit} from 'express-rate-limit';
import * as samlify from 'samlify';
import {ManagementClient} from 'auth0';
const work=process.env.E2E_M37C_WORK;
test.skip(!work,'Run make e2e-self-service');
test.use({trace:'off'});
const host='localhost:9548',origin=`https://${host}`,idpBase='https://127.0.0.1:9693',app='https://127.0.0.1:9694';
const pem=async name=>(await readFile(`${work}/${name}`,'utf8')).trim();
samlify.setSchemaValidator({validate:async()=>'skipped'});
const REDIRECT=samlify.Constants.namespace.binding.redirect;
const first=v=>Array.isArray(v)?v[0]:v;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let servers=[],mgmt,profileId,ticketURL;
const issued=[];
async function listen(handler,port){const s=https.createServer({key:await readFile(`${work}/key.pem`),cert:await readFile(`${work}/cert.pem`)},handler).listen(port,'127.0.0.1');await once(s,'listening');servers.push(s);}
async function record(v){issued.push(v);await writeFile(`${work}/issued.json`,JSON.stringify(issued),{mode:0o600});}

test.beforeAll(async()=>{
 const r=await fetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:'m37c-admin',client_secret:process.env.E2E_M37C_ADMIN_SECRET,audience:`${origin}/api/v2/`})});
 expect(r.status).toBe(200);
 mgmt=new ManagementClient({domain:host,token:(await r.json()).access_token,maxRetries:0});
 const profile=await mgmt.selfServiceProfiles.create({name:'Partners',allowed_strategies:['samlp','oidc'],branding:{colors:{primary:'#116a7b'}},
  user_attributes:[{name:'email',description:'Work email',is_optional:false}]});
 profileId=profile.id;
 await mgmt.selfServiceProfiles.customText.set(profileId,'en','get-started',{introduction:'Welcome, <b>Partner Corp</b>. <script>window.pwned=1</script>'});
 ticketURL=(await mgmt.selfServiceProfiles.ssoTicket.create(profileId,{connection_config:{name:'partner-saml'},enabled_clients:['m37c-app'],
  provisioning_config:{scopes:['get:users','post:users']},ttl_sec:3600})).ticket;
 await record(new URL(ticketURL).searchParams.get('ticket'));
 // The customer's identity provider: samlify, with zeroauthy's SP metadata
 // read once the assistant has created the connection.
 const idp=samlify.IdentityProvider({entityID:'urn:e2e:partner-idp',privateKey:await pem('idp-key.pem'),signingCert:await pem('idp-cert.pem'),wantAuthnRequestsSigned:false,
  nameIDFormat:['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],singleSignOnService:[{Binding:REDIRECT,Location:`${idpBase}/sso`}]});
 const user={email:'carol@partner.example.test',name:'Partner Carol'};
 const limiter=rateLimit({windowMs:60_000,limit:200,standardHeaders:true,legacyHeaders:false});
 const idpApp=express();idpApp.use(limiter);
 idpApp.get('/sso',async(req,res)=>{try{
  const spEntity=samlify.ServiceProvider({metadata:await (await fetch(`${origin}/samlp/metadata?connection=partner-saml`)).text()});
  const {extract}=await idp.parseLoginRequest(spEntity,'redirect',{query:req.query});
  const acs=first(spEntity.entityMeta.getAssertionConsumerService('post'));
  const replace=template=>{const now=new Date(),later=new Date(now.getTime()+300_000),id='_'+randomUUID();
   const scalar=samlify.SamlLib.replaceTagsByValue(template,{ID:id,AssertionID:'_'+randomUUID(),Destination:acs,Audience:spEntity.entityMeta.getEntityID(),SubjectRecipient:acs,Issuer:idp.entityMeta.getEntityID(),
    IssueInstant:now.toISOString(),StatusCode:'urn:oasis:names:tc:SAML:2.0:status:Success',ConditionsNotBefore:now.toISOString(),ConditionsNotOnOrAfter:later.toISOString(),SubjectConfirmationDataNotOnOrAfter:later.toISOString(),
    NameIDFormat:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',NameID:user.email,InResponseTo:extract.request.id});
   const authn=`<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="_s${randomUUID()}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`;
   const attrs=`<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue xsi:type="xs:string">${esc(user.email)}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="name"><saml:AttributeValue xsi:type="xs:string">${esc(user.name)}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`;
   const context=scalar.replace('{AuthnStatement}',authn).replace('{AttributeStatement}',attrs);
   if(context.includes('{'))throw new Error('unrendered template tag');
   return {id,context};};
  const out=await idp.createLoginResponse(spEntity,{extract},'post',user,replace,false,req.query.RelayState);
  res.send(`<!doctype html><title>Partner IdP</title><form method="post" action="${esc(out.entityEndpoint)}"><input type="hidden" name="SAMLResponse" value="${esc(out.context)}"><input type="hidden" name="RelayState" value="${esc(out.relayState??req.query.RelayState??'')}"></form><script>document.forms[0].submit()</script>`);
 }catch(e){res.status(400).send(esc(e.message??e))}});
 await listen(idpApp,9693);
 const appSrv=express();appSrv.use(limiter);appSrv.get('/raw',(_req,res)=>res.send('<!doctype html><title>Partner portal callback</title>'));
 await listen(appSrv,9694);
});
test.afterAll(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}});

test('the customer administrator configures SAML through the assistant and signs in through it',async({page})=>{
 await page.goto(ticketURL);
 // The token leaves the URL at once.
 await page.waitForURL(`${origin}/self-service/connections-flow`);
 await expect(page.locator('h1')).toHaveText('Single sign-on setup');
 await expect(page.locator('.intro b')).toHaveText('Partner Corp');
 expect(await page.evaluate(()=>window.pwned)).toBeUndefined();
 await expect(page.locator('body')).toContainText('urn:auth0:ssso:partner-saml');
 await expect(page.locator('#strategy option')).toHaveText(['samlp','oidc']);
 await page.selectOption('#strategy','samlp');
 await page.fill('#sign_in_url',`${idpBase}/sso`);
 await page.fill('#signing_cert',await pem('idp-cert.pem'));
 await page.click('form:has(input[value=configure]) button[type=submit]');
 await expect(page.locator('.notice')).toContainText('The connection is created');
 const conns=await mgmt.connections.list({name:'partner-saml'});
 const conn=conns.data[0];
 expect(conn.strategy).toBe('samlp');
 expect((await mgmt.connections.clients.get(conn.id)).data.map(c=>c.client_id)).toEqual(['m37c-app']);
 // Test sign-in through the new connection.
 const test=page.locator('a',{hasText:'Sign in through the new connection'});
 const href=await test.getAttribute('href');
 expect(new URL(href).searchParams.get('connection')).toBe('partner-saml');
 await test.click();
 await page.waitForURL(url=>url.origin===app||url.pathname==='/u/consent');
 if(page.url().includes('/u/consent'))await page.click('button[value=accept]');
 await page.waitForURL(url=>url.origin===app);
 const cb=new URL(page.url());
 expect(cb.searchParams.get('error')).toBeNull();
 expect(cb.searchParams.get('code')).toBeTruthy();
 const users=await mgmt.users.list({q:'email:"carol@partner.example.test"',search_engine:'v3'});
 expect(users.data.map(u=>u.user_id)).toEqual([expect.stringMatching(/^samlp\|partner-saml\|/)]);
 // Back in the assistant: SCIM token, shown once, with the ticket's scopes.
 await page.goto(`${origin}/self-service/connections-flow`);
 await page.click('form:has(input[value=scim]) button');
 const token=(await page.locator('#scim-token').innerText()).trim();
 await record(token);
 const spc=await fetch(`${origin}/scim/v2/connections/${conn.id}/ServiceProviderConfig`,{headers:{authorization:`Bearer ${token}`}});
 expect(spc.status).toBe(200);
 const write=await fetch(`${origin}/scim/v2/connections/${conn.id}/Users/x`,{method:'DELETE',headers:{authorization:`Bearer ${token}`}});
 expect(write.status).toBe(403);
 // Finishing ends the ticket.
 await page.click('form:has(input[value=finish]) button');
 await expect(page.locator('body')).toContainText('Setup is complete');
 const again=await page.goto(ticketURL);
 expect(again.status()).toBe(404);
});
