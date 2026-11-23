// Original Plan 37b acceptance: zeroauthy as WS-Federation identity provider
// and relying party over real HTTPS and a real browser. The fixtures sign
// and verify XML with the pinned xml-crypto, independently of zeroauthy's
// own XML code. Run through make e2e-wsfed.
import {test,expect} from '@playwright/test';
import {once} from 'node:events';
import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {appendFile,readFile} from 'node:fs/promises';
import https from 'node:https';
import express from 'express';
import {rateLimit} from 'express-rate-limit';
import {SignedXml} from 'xml-crypto';
const work=process.env.E2E_M37B_WORK;
test.skip(!work,'Run make e2e-wsfed');
test.use({trace:'off'});
const origin='https://localhost:9545',rp='https://127.0.0.1:9673',idpBase='https://127.0.0.1:9683';
const realm='urn:e2e:wsfed-rp';
const credentials=work?JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8')):{};
const pem=async name=>(await readFile(`${work}/${name}`,'utf8')).trim();
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const unesc=s=>s.replace(/&(lt|gt|quot|apos|amp);/g,(_,e)=>({lt:'<',gt:'>',quot:'"',apos:"'",amp:'&'}[e]));
let servers=[],events={};
async function listen(app,port){const s=https.createServer({key:await readFile(`${work}/key.pem`),cert:await readFile(`${work}/cert.pem`)},app).listen(port,'127.0.0.1');await once(s,'listening');servers.push(s);}
const toPEM=b64=>`-----BEGIN CERTIFICATE-----\n${b64.replace(/\s+/g,'').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;

// verifyToken checks a wresult the way a relying party library does: the
// SAML 1.1 assertion's enveloped signature (reference = AssertionID) with a
// certificate from zeroauthy's federation metadata; values are read only
// from the signed reference.
function verifyToken(wresult,certs){
 const assertion=wresult.match(/<saml:Assertion[\s\S]*<\/saml:Assertion>/)?.[0];
 const signature=assertion?.match(/<ds:Signature[\s\S]*<\/ds:Signature>/)?.[0];
 if(!assertion||!signature)throw new Error('no signed assertion');
 for(const publicCert of certs){
  const sig=new SignedXml({publicCert,idAttribute:'AssertionID'});
  sig.loadSignature(signature);
  try{if(!sig.checkSignature(assertion))continue}catch{continue}
  const [signed]=sig.getSignedReferences();
  const attr=name=>unesc(signed.match(new RegExp(`AttributeName="${name}"[^>]*>\\s*<saml:AttributeValue>([^<]*)<`))?.[1]??'');
  return {version:`${signed.match(/MajorVersion="(\d)"/)?.[1]}.${signed.match(/MinorVersion="(\d)"/)?.[1]}`,audience:unesc(signed.match(/<saml:Audience>([^<]*)</)?.[1]??''),
   nameID:unesc(signed.match(/<saml:NameIdentifier[^>]*>([^<]*)</)?.[1]??''),email:attr('emailaddress'),
   context:unesc(wresult.match(/RequestSecurityTokenResponse[^>]*Context="([^"]*)"/)?.[1]??'')};
 }
 throw new Error('signature does not verify with the metadata certificates');
}

// signToken is the identity-provider fixture's SAML 1.1 token, signed as
// node-wsfed does (exclusive c14n, RSA-SHA256, Signature last).
function signToken({audience,nameID,email,key,cert}){
 const now=new Date(),later=new Date(now.getTime()+3600_000),id='_'+randomUUID().replace(/-/g,'');
 const subject=`<saml:Subject><saml:NameIdentifier Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">${esc(nameID)}</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</saml:ConfirmationMethod></saml:SubjectConfirmation></saml:Subject>`;
 const xml=`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="${id}" Issuer="urn:e2e:sts" IssueInstant="${now.toISOString()}">`+
  `<saml:Conditions NotBefore="${now.toISOString()}" NotOnOrAfter="${later.toISOString()}"><saml:AudienceRestrictionCondition><saml:Audience>${esc(audience)}</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions>`+
  `<saml:AttributeStatement>${subject}<saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="emailaddress"><saml:AttributeValue>${esc(email)}</saml:AttributeValue></saml:Attribute>`+
  `<saml:Attribute AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims" AttributeName="name"><saml:AttributeValue>STS Carol</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`+
  `<saml:AuthenticationStatement AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password" AuthenticationInstant="${now.toISOString()}">${subject}</saml:AuthenticationStatement></saml:Assertion>`;
 const sig=new SignedXml({privateKey:key,publicCert:cert,idAttribute:'AssertionID',signatureAlgorithm:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',canonicalizationAlgorithm:'http://www.w3.org/2001/10/xml-exc-c14n#'});
 sig.addReference({xpath:"//*[local-name(.)='Assertion']",digestAlgorithm:'http://www.w3.org/2001/04/xmlenc#sha256',transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature','http://www.w3.org/2001/10/xml-exc-c14n#']});
 sig.computeSignature(xml,{prefix:'ds',location:{reference:"//*[local-name(.)='AuthenticationStatement']",action:'after'}});
 return `<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust"><t:RequestedSecurityToken>${sig.getSignedXml()}</t:RequestedSecurityToken></t:RequestSecurityTokenResponse>`;
}

test.beforeAll(async()=>{
 const limiter=rateLimit({windowMs:60_000,limit:200,standardHeaders:true,legacyHeaders:false});
 // zeroauthy as IdP: the relying-party fixture trusts the certificates of
 // zeroauthy's federation metadata.
 const metadata=await (await fetch(`${origin}/wsfed/FederationMetadata/2007-06/FederationMetadata.xml`)).text();
 const certs=[...metadata.matchAll(/<X509Certificate>([^<]+)</g)].map(m=>toPEM(m[1]));
 expect(certs.length).toBeGreaterThan(0);
 expect(metadata).toContain(`<Address>${origin}/wsfed</Address>`);
 const rpApp=express();rpApp.use(limiter);rpApp.use(express.urlencoded({extended:false,limit:'256kb'}));
 rpApp.get('/login',(req,res)=>{events.wctx=randomBytes(8).toString('hex');res.redirect(`${origin}/wsfed/m37b-rp?${new URLSearchParams({wa:'wsignin1.0',wtrealm:realm,wreply:`${rp}/callback`,wctx:events.wctx})}`)});
 rpApp.post('/callback',(req,res)=>{try{if(req.body.wa!=='wsignin1.0'||req.body.wctx!==events.wctx)throw new Error('wa or wctx mismatch');res.json(verifyToken(req.body.wresult,certs))}catch(e){res.status(400).json({error:String(e.message)})}});
 rpApp.get('/logout',(_req,res)=>res.redirect(`${origin}/wsfed/m37b-rp?${new URLSearchParams({wa:'wsignout1.0',wreply:`${rp}/bye`})}`));
 rpApp.get('/bye',(_req,res)=>res.send('<!doctype html><title>Plan37b signed out</title>signed out'));
 rpApp.get('/raw',(_req,res)=>res.send('<!doctype html><title>Plan37b callback</title>'));
 await listen(rpApp,9673);
 // zeroauthy as RP: the identity-provider fixture (an ADFS stand-in).
 const key=await pem('idp-key.pem'),cert=await pem('idp-cert.pem');
 const idpApp=express();idpApp.use(limiter);
 idpApp.get('/adfs/ls/',(req,res)=>{
  const q=req.query;
  if(q.wa==='wsignout1.0'){events.signout={wreply:q.wreply};return res.redirect(String(q.wreply))}
  events.signin={wtrealm:q.wtrealm,wreply:q.wreply};
  if(q.wa!=='wsignin1.0'||!q.wctx||!String(q.wreply).startsWith(origin))return res.status(400).send('bad request');
  const wresult=signToken({audience:String(q.wtrealm),nameID:'carol@sts.example.test',email:'carol@sts.example.test',key,cert});
  res.send(`<!doctype html><title>STS</title><form method="post" action="${esc(q.wreply)}"><input type="hidden" name="wa" value="wsignin1.0"><input type="hidden" name="wresult" value="${esc(wresult)}"><input type="hidden" name="wctx" value="${esc(q.wctx)}"></form><script>document.forms[0].submit()</script>`);
 });
 await listen(idpApp,9683);
});
test.afterAll(async()=>{for(const s of servers){s.closeAllConnections();await new Promise(r=>s.close(r));}});
test.beforeEach(async({page})=>{page.on('console',msg=>{void appendFile(`${work}/browser-console.log`,msg.text()+'\n',{mode:0o600})});});
async function json(page){return JSON.parse(await page.locator('body').innerText());}
async function hostedLogin(page){await page.waitForURL(/\/u\/login/);await page.fill('#username','alice@example.test');await page.fill('#password',credentials.password);await page.click('button[type=submit]');}

test('a relying party signs in through the zeroauthy WS-Fed add-on and signs out',async({page})=>{
 await page.goto(`${rp}/login`);await hostedLogin(page);
 await page.waitForURL(`${rp}/callback`);const login=await json(page);
 expect(login.error).toBeUndefined();
 expect(login).toMatchObject({version:'1.1',audience:realm,email:'alice@example.test',context:events.wctx});
 expect(login.nameID).toMatch(/^auth0\|/);
 // Signed in: a second sign-in completes without a prompt.
 await page.goto(`${rp}/login`);await page.waitForURL(`${rp}/callback`);expect((await json(page)).context).toBe(events.wctx);
 // wsignout1.0 ends the session and returns to the allowed wreply.
 await page.goto(`${rp}/logout`);await page.waitForURL(`${rp}/bye`);
 await page.goto(`${rp}/login`);await page.waitForURL(/\/u\/login/);
});

test('a wreply outside the callbacks gets an error page and no token',async({page})=>{
 const r=await page.goto(`${origin}/wsfed/m37b-rp?${new URLSearchParams({wtrealm:realm,wreply:'https://127.0.0.1:9673/elsewhere'})}`);
 expect(r.status()).toBe(400);expect(await page.content()).not.toContain('wresult');
});

test('zeroauthy as relying party signs in through a WS-Fed identity provider and signs out there',async({page})=>{
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex');
 const query=new URLSearchParams({client_id:'m37b-app',connection:'corp-adfs',redirect_uri:`${rp}/raw`,response_type:'code',scope:'openid profile email',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
 await page.goto(`${origin}/authorize?${query}`);
 await page.waitForURL(url=>url.pathname==='/raw'||url.pathname==='/u/consent');if(page.url().includes('/u/consent'))await page.click('button[value=accept]');
 await page.waitForURL(new RegExp('/raw\\?'));const cb=new URL(page.url());expect(cb.searchParams.get('error_description')).toBeNull();expect(cb.searchParams.get('state')).toBe(state);
 expect(events.signin).toEqual({wtrealm:'urn:auth0:wsfed:corp-adfs',wreply:`${origin}/login/callback`});
 const r=await fetch(`${origin}/oauth/token`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:'m37b-app',redirect_uri:`${rp}/raw`,code:cb.searchParams.get('code'),code_verifier:verifier})});
 const body=await r.json();expect(r.status).toBe(200);
 const claims=JSON.parse(Buffer.from(body.id_token.split('.')[1],'base64url'));
 expect(claims.nonce).toBe(nonce);expect(claims.sub).toBe('adfs|corp-adfs|carol@sts.example.test');expect(claims.email).toBe('carol@sts.example.test');expect(claims.name).toBe('STS Carol');
 // Logout hands the browser to the IdP's wsignout1.0 with wreply = returnTo.
 await page.goto(`${origin}/v2/logout?${new URLSearchParams({client_id:'m37b-app',returnTo:`${rp}/raw`})}`);
 await page.waitForURL(url=>url.origin===rp&&url.pathname==='/raw');
 expect(events.signout).toEqual({wreply:`${rp}/raw`});
});
