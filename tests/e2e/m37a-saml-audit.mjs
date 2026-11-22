// Plan 37a: generated secrets and private keys never reach logs.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
const work=process.env.E2E_M37A_WORK;
const credentials=JSON.parse(await readFile(`${work}/private-credentials.json`,'utf8'));
const keyBody=async f=>(await readFile(`${work}/${f}`,'utf8')).split('\n').filter(l=>l&&!l.startsWith('-----')).slice(1,3).join('');
const known=[...Object.values(credentials),await keyBody('idp-key.pem'),await keyBody('sp-key.pem')];
for(const name of ['server.log','playwright.log','browser-console.log']){let text;try{text=await readFile(`${work}/${name}`,'utf8')}catch(e){if(e.code==='ENOENT')continue;throw e}
 for(const value of known)assert.equal(text.includes(value),false,`${name} exposed a private value`);}
console.log('Plan 37a secret scan passed');
