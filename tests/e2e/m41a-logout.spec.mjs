import {test,expect} from '@playwright/test';
import {once} from 'node:events';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {appendFile,readFile} from 'node:fs/promises';
import https from 'node:https';
import express from 'express';
import sdk from 'express-openid-connect';
import {work,origin,rp,credentials,remember,tokens,management,decode} from './m41a-node-auth0.mjs';
test.skip(!work,'Run make e2e-logout');
test.use({trace:'off'});
const ACR='http://schemas.openid.net/pape/policies/2007/06/multi-factor';
let server,received;
test.beforeEach(async({page})=>{
 received=[];const rows=new Map();const store={get:(id,cb)=>cb(null,rows.get(id)),set:(id,value,cb)=>{rows.set(id,value);cb(null)},destroy:(id,cb)=>{rows.delete(id);cb(null)}};
 const app=express();app.use((req,res,next)=>{if(req.path==='/backchannel-logout')res.on('finish',()=>received.push(res.statusCode));next()});
 app.use(sdk.auth({issuerBaseURL:origin,baseURL:rp,clientID:'m41a-web',clientSecret:credentials.web,secret:randomBytes(32).toString('hex'),authRequired:false,authorizationParams:{response_type:'code',scope:'openid profile email'},backchannelLogout:{store},routes:{backchannelLogout:'/backchannel-logout'}}));
 app.get(['/','/status'],(req,res)=>res.json({authenticated:req.oidc.isAuthenticated()}));app.get('/raw',(_req,res)=>res.send('<!doctype html><title>Plan41a callback</title>'));
 server=https.createServer({key:await readFile(`${work}/key.pem`),cert:await readFile(`${work}/cert.pem`)},app).listen(9643,'127.0.0.1');await once(server,'listening');
 page.on('console',msg=>{void appendFile(`${work}/browser-console.log`,msg.text()+'\n',{mode:0o600})});
});
test.afterEach(async()=>{if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve))}});
async function login(page){await page.waitForURL(/\/u\/login/);await page.fill('#username','alice@example.test');await page.fill('#password',credentials.password);await page.click('button[type=submit]'); if(page.url().includes('/u/consent'))await page.click('button[value=accept]')}
async function webLogin(page){await page.goto(`${rp}/login`);await login(page);await page.waitForURL(`${rp}/`);expect(JSON.parse(await page.locator('body').innerText()).authenticated).toBe(true)}
async function authorization(page,extra={}){
 const verifier=randomBytes(32).toString('base64url'),state=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex');
 const query=new URLSearchParams({client_id:'m41a-spa',redirect_uri:`${rp}/raw`,response_type:'code',scope:'openid profile email offline_access',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',...extra});
 await page.goto(`${origin}/authorize?${query}`);if(page.url().includes('/u/consent'))await page.click('button[value=accept]');return {verifier,state,nonce};
}
async function exchange(page,flow){await page.waitForURL(url=>url.pathname==='/raw'||url.pathname==='/u/consent');if(page.url().includes('/u/consent'))await page.click('button[value=accept]');await page.waitForURL(new RegExp('/raw\\?'));const cb=new URL(page.url());expect(cb.searchParams.get('state')).toBe(flow.state);const result=await tokens({grant_type:'authorization_code',client_id:'m41a-spa',redirect_uri:`${rp}/raw`,code:cb.searchParams.get('code'),code_verifier:flow.verifier});expect(result.status).toBe(200);expect(decode(result.body.id_token).nonce).toBe(flow.nonce);return result.body;}
async function checkLoggedOut(page){await expect.poll(async()=>{await page.goto(`${rp}/status`);return JSON.parse(await page.locator('body').innerText()).authenticated}).toBe(false);expect(received).toContain(204)}
function totp(secret){const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';for(const ch of secret.replace(/=+$/,''))bits+=alphabet.indexOf(ch).toString(2).padStart(5,'0');const key=Buffer.from(bits.match(/.{8}/g).map(s=>parseInt(s,2)));const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const digest=createHmac('sha1',key).update(counter).digest(),off=digest.at(-1)&15;return String((digest.readUInt32BE(off)&0x7fffffff)%1000000).padStart(6,'0')}
test('another client logout ends the Express session through a verified back-channel token',async({page})=>{
 await webLogin(page);const body=await exchange(page,await authorization(page));expect(body.refresh_token).toBeTruthy();
 await page.goto(`${origin}/oidc/logout?${new URLSearchParams({id_token_hint:body.id_token,client_id:'m41a-spa',post_logout_redirect_uri:`${rp}/raw`})}`);
 await checkLoggedOut(page);
});
test('MFA step-up enrolls a real factor and returns requested ACR without repeating the prompt',async({page})=>{
 await webLogin(page);const flow=await authorization(page,{acr_values:ACR});await page.waitForURL(/\/u\/mfa-otp-enrollment/);
 const secret=await remember((await page.locator('#mfa-secret').innerText()).trim());await page.fill('#code',totp(secret));await page.click('button[type=submit]');
 await page.locator('#recovery-code').waitFor();await remember((await page.locator('#recovery-code').innerText()).trim());await page.check('input[name=ack]');await page.click('button[type=submit]');
 const body=await exchange(page,flow);const claims=decode(body.id_token);expect(claims.acr).toBe(ACR);expect(claims.amr).toContain('mfa');
 const next=await exchange(page,await authorization(page,{acr_values:ACR,prompt:'none'}));expect(decode(next.id_token).acr).toBe(ACR);
});
test('pinned upstream global revocation ends linked-user SSO, refresh tokens and the Express session',async({page})=>{
 await webLogin(page);const body=await exchange(page,await authorization(page));const sid=decode(body.id_token).sid;expect(sid).toBeTruthy();
 const fixture=await fetch('https://127.0.0.1:9743/global-jwt',{method:'POST'});expect(fixture.status).toBe(200);const jwt=await remember((await fixture.json()).token);
 const revoke=()=>fetch(`${origin}/oauth/global-token-revocation/connection/Enterprise`,{method:'POST',headers:{authorization:`Bearer ${jwt}`,'content-type':'application/json'},body:JSON.stringify({sub_id:{format:'iss_sub',iss:'https://example.com',sub:'upstream-user'}})});
 expect((await revoke()).status).toBe(204);expect((await revoke()).status).toBe(401);
 expect((await tokens({grant_type:'refresh_token',client_id:'m41a-spa',refresh_token:body.refresh_token})).body.error).toBe('invalid_grant');
 await assertSessionGone(sid);await checkLoggedOut(page);
});
async function assertSessionGone(sid){const m=await management();let gone=false;try{await m.sessions.get(sid)}catch(e){gone=e.statusCode===404||e.status===404}expect(gone).toBe(true)}
