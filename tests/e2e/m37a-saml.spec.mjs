// Original Plan 37a acceptance: pinned @node-saml/node-saml (service
// provider) and samlify (identity provider) against zeroauthy over real
// HTTPS and a real browser. Run through make e2e-saml.
import {test,expect} from '@playwright/test';
import {once} from 'node:events';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {appendFile,readFile} from 'node:fs/promises';
import https from 'node:https';
import express from 'express';
import {rateLimit} from 'express-rate-limit';
import {SAML,ValidateInResponseTo} from '@node-saml/node-saml';
import * as samlify from 'samlify';
const work=process.env.E2E_M37A_WORK;
test.skip(!work,'Run make e2e-saml');
test.use({trace:'off'});
const origin='https://localhost:9543',sp='https://127.0.0.1:9653',idpBase='https://127.0.0.1:9663';
const credentials=work?JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8')):{};
const pem=async name=>(await readFile(`${work}/${name}`,'utf8')).trim();
// The fixture IdP only needs to read zeroauthy's messages; XML schema
// validation of zeroauthy's output is not what this lane measures.
samlify.setSchemaValidator({validate:async()=>'skipped'});
const REDIRECT=samlify.Constants.namespace.binding.redirect;
let servers=[],saml,events;
const first=v=>Array.isArray(v)?v[0]:v;
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
async function listen(app,port){const s=https.createServer({key:await readFile(`${work}/key.pem`),cert:await readFile(`${work}/cert.pem`)},app).listen(port,'127.0.0.1');await once(s,'listening');servers.push(s);}
function rawQuery(req){const i=req.originalUrl.indexOf('?');return i<0?'':req.originalUrl.slice(i+1);}
// The redirect binding signs SAMLRequest/SAMLResponse&RelayState&SigAlg in
// the received order (SAML bindings §3.4.4.1).
function octets(req,param){return rawQuery(req).split('&').filter(p=>[param,'RelayState','SigAlg'].includes(p.split('=')[0])).join('&');}
test.beforeAll(async()=>{
 const limiter=rateLimit({windowMs:60_000,limit:200,standardHeaders:true,legacyHeaders:false});
 // zeroauthy as IdP: node-saml as the service provider.
 const metadata=await (await fetch(`${origin}/samlp/metadata/m37a-sp`)).text();
 const idpCert=metadata.match(/<(?:ds:)?X509Certificate>([^<]+)</)[1].replace(/\s+/g,'');
 saml=new SAML({entryPoint:`${origin}/samlp/m37a-sp`,logoutUrl:`${origin}/samlp/m37a-sp/logout`,issuer:'urn:e2e:node-saml',audience:'urn:e2e:node-saml',callbackUrl:`${sp}/acs`,logoutCallbackUrl:`${sp}/slo`,
  idpCert,privateKey:await pem('sp-key.pem'),signatureAlgorithm:'sha256',wantAssertionsSigned:true,wantAuthnResponseSigned:false,validateInResponseTo:ValidateInResponseTo.always});
 events={profile:null,logoutRequest:null};
 const spApp=express();spApp.use(limiter);spApp.use(express.urlencoded({extended:false,limit:'256kb'}));
 spApp.get('/login',async(req,res)=>res.redirect(await saml.getAuthorizeUrlAsync(String(req.query.relay??''),undefined,{})));
 spApp.post('/acs',async(req,res)=>{try{const r=await saml.validatePostResponseAsync(req.body);events.profile=r.profile;res.json({nameID:r.profile.nameID,email:r.profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'],sessionIndex:r.profile.sessionIndex,relay:req.body.RelayState})}catch(e){res.status(400).json({error:String(e.message)})}});
 spApp.get('/logout',async(req,res)=>res.redirect(await saml.getLogoutUrlAsync(events.profile,'relay-logout',{})));
 spApp.get('/slo',async(req,res)=>{try{const r=await saml.validateRedirectAsync(req.query,rawQuery(req));res.json({loggedOut:r.loggedOut,relay:req.query.RelayState,signed:'Signature' in req.query})}catch(e){res.status(400).json({error:String(e.message)})}});
 spApp.get('/raw',(_req,res)=>res.send('<!doctype html><title>Plan37a callback</title>'));
 await listen(spApp,9653);
 // zeroauthy as SP: samlify as the identity provider.
 const spMetadata=await (await fetch(`${origin}/samlp/metadata?connection=corp-saml`)).text();
 // zeroauthy requires signed logout messages from the IdP.
 const spEntity=samlify.ServiceProvider({metadata:spMetadata,wantLogoutResponseSigned:true});
 const idp=samlify.IdentityProvider({entityID:'urn:e2e:samlify',privateKey:await pem('idp-key.pem'),signingCert:await pem('idp-cert.pem'),wantAuthnRequestsSigned:false,wantLogoutRequestSigned:true,
  nameIDFormat:['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'],singleSignOnService:[{Binding:REDIRECT,Location:`${idpBase}/sso`}],singleLogoutService:[{Binding:REDIRECT,Location:`${idpBase}/slo`}]});
 const user={email:'bob@idp.example.test',name:'Samlify Bob',session:'_s'+randomUUID()};
 const idpApp=express();idpApp.use(limiter);
 idpApp.get('/sso',async(req,res)=>{
  const {extract}=await idp.parseLoginRequest(spEntity,'redirect',{query:req.query});
  const acs=first(spEntity.entityMeta.getAssertionConsumerService('post'));
  // replaceTagsByValue escapes every value: render the scalar tags, then
  // splice in the two statements (their values escaped here).
  const replace=template=>{const now=new Date(),later=new Date(now.getTime()+300_000),id='_'+randomUUID();
   const scalar=samlify.SamlLib.replaceTagsByValue(template,{ID:id,AssertionID:'_'+randomUUID(),Destination:acs,Audience:spEntity.entityMeta.getEntityID(),SubjectRecipient:acs,Issuer:idp.entityMeta.getEntityID(),
    IssueInstant:now.toISOString(),StatusCode:'urn:oasis:names:tc:SAML:2.0:status:Success',ConditionsNotBefore:now.toISOString(),ConditionsNotOnOrAfter:later.toISOString(),SubjectConfirmationDataNotOnOrAfter:later.toISOString(),
    NameIDFormat:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',NameID:user.email,InResponseTo:extract.request.id});
   const authn=`<saml:AuthnStatement AuthnInstant="${now.toISOString()}" SessionIndex="${esc(user.session)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`;
   const attrs=`<saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue xsi:type="xs:string">${esc(user.email)}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="displayName"><saml:AttributeValue xsi:type="xs:string">${esc(user.name)}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`;
   const context=scalar.replace('{AuthnStatement}',authn).replace('{AttributeStatement}',attrs);
   if(context.includes('{'))throw new Error('unrendered template tag');
   return {id,context};};
  const r=await idp.createLoginResponse(spEntity,{extract},'post',user,replace,false,req.query.RelayState);
  res.send(`<!doctype html><title>samlify</title><form method="post" action="${esc(r.entityEndpoint)}"><input type="hidden" name="SAMLResponse" value="${esc(r.context)}"><input type="hidden" name="RelayState" value="${esc(r.relayState??req.query.RelayState??'')}"></form><script>document.forms[0].submit()</script>`);
 });
 idpApp.get('/slo',async(req,res)=>{
  try{const {extract}=await idp.parseLogoutRequest(spEntity,'redirect',{query:req.query,octetString:octets(req,'SAMLRequest')});
   events.logoutRequest={nameID:extract.nameID,sessionIndex:extract.sessionIndex,signed:'Signature' in req.query,expected:user.session};
   const r=await idp.createLogoutResponse(spEntity,{extract},'redirect',req.query.RelayState);res.redirect(r.context);}
  catch(e){res.status(400).send(esc(e.message??e))}
 });
 await listen(idpApp,9663);
});
test.afterAll(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}});
test.beforeEach(async({page})=>{page.on('console',msg=>{void appendFile(`${work}/browser-console.log`,msg.text()+'\n',{mode:0o600})});});
async function json(page){return JSON.parse(await page.locator('body').innerText());}
async function hostedLogin(page){await page.waitForURL(/\/u\/login/);await page.fill('#username','alice@example.test');await page.fill('#password',credentials.password);await page.click('button[type=submit]');}

test('node-saml logs in through the zeroauthy IdP add-on and single logout is signed both ways',async({page})=>{
 await page.goto(`${sp}/login?relay=relay-login`);await hostedLogin(page);
 await page.waitForURL(`${sp}/acs`);const login=await json(page);
 expect(login.error).toBeUndefined();expect(login.email).toBe('alice@example.test');expect(login.relay).toBe('relay-login');expect(login.sessionIndex).toBeTruthy();
 // Already signed in: a second SP-initiated login completes without a prompt.
 await page.goto(`${sp}/login?relay=again`);await page.waitForURL(`${sp}/acs`);expect((await json(page)).relay).toBe('again');
 // node-saml signs the LogoutRequest; zeroauthy verifies it against the
 // add-on certificate and answers with a signed LogoutResponse.
 await page.goto(`${sp}/logout`);await page.waitForURL(url=>url.pathname==='/slo');const out=await json(page);
 expect(out).toEqual({loggedOut:true,relay:'relay-logout',signed:true});
 await page.goto(`${sp}/login?relay=after`);await page.waitForURL(/\/u\/login/);
});

test('an unsigned LogoutRequest is refused when the add-on has a signing certificate',async({page})=>{
 const unsigned=new SAML({entryPoint:`${origin}/samlp/m37a-sp`,logoutUrl:`${origin}/samlp/m37a-sp/logout`,issuer:'urn:e2e:node-saml',callbackUrl:`${sp}/acs`,idpCert:'unused'});
 const url=await unsigned.getLogoutUrlAsync({issuer:'urn:e2e:node-saml',nameID:'alice@example.test',nameIDFormat:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'},'',{});
 const r=await page.goto(url);expect(r.status()).toBe(400);
});

test('zeroauthy as SP logs in through samlify and logs out upstream with a signed LogoutRequest',async({page})=>{
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex');
 const query=new URLSearchParams({client_id:'m37a-app',connection:'corp-saml',redirect_uri:`${sp}/raw`,response_type:'code',scope:'openid profile email',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
 await page.goto(`${origin}/authorize?${query}`);
 await page.waitForURL(url=>url.pathname==='/raw'||url.pathname==='/u/consent');if(page.url().includes('/u/consent'))await page.click('button[value=accept]');
 await page.waitForURL(new RegExp('/raw\\?'));const cb=new URL(page.url());expect(cb.searchParams.get('error_description')).toBeNull();expect(cb.searchParams.get('state')).toBe(state);
 const r=await fetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:'m37a-app',redirect_uri:`${sp}/raw`,code:cb.searchParams.get('code'),code_verifier:verifier})});
 const body=await r.json();expect(r.status).toBe(200);
 const claims=JSON.parse(Buffer.from(body.id_token.split('.')[1],'base64url'));
 expect(claims.nonce).toBe(nonce);expect(claims.sub).toMatch(/^samlp\|corp-saml\|/);expect(claims.email).toBe('bob@idp.example.test');expect(claims.name).toBe('Samlify Bob');
 // zeroauthy logout reaches the samlify IdP with a signed LogoutRequest for
 // the upstream session, then finishes at returnTo.
 await page.goto(`${origin}/v2/logout?${new URLSearchParams({client_id:'m37a-app',returnTo:`${sp}/raw`})}`);
 await page.waitForURL(url=>url.origin===sp&&url.pathname==='/raw');
 expect(events.logoutRequest).toMatchObject({nameID:'bob@idp.example.test',signed:true});expect(events.logoutRequest.sessionIndex).toBe(events.logoutRequest.expected);
 const silent=new URLSearchParams({client_id:'m37a-app',redirect_uri:`${sp}/raw`,response_type:'code',scope:'openid',state,prompt:'none',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
 await page.goto(`${origin}/authorize?${silent}`);await page.waitForURL(new RegExp('/raw\\?'));expect(new URL(page.url()).searchParams.get('error')).toBe('login_required');
});
