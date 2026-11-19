import assert from 'node:assert/strict';
import {spawnSync}from 'node:child_process';
import {mkdtempSync,rmSync,readFileSync,writeFileSync}from 'node:fs';
const home=mkdtempSync('/tmp/za36-cli-');
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:'m24-admin',AUTH0_CLIENT_SECRET:'m24-admin-secret-not-for-production'};
try{const {back}=JSON.parse(readFileSync(`${process.env.E2E_M36_WORK}/connections.json`,'utf8'));const r=spawnSync(process.env.AUTH0_BIN,['api','get',`connections/${back}/keys`,'--no-input','--no-color'],{env,encoding:'utf8',timeout:60000});assert.equal(r.status,0,r.stderr);const rows=JSON.parse(r.stdout);assert.ok(rows.length>=4);assert.ok(rows.every(k=>!JSON.stringify(k).includes('PRIVATE KEY')));writeFileSync(`${process.env.E2E_M36_WORK}/cli-public-keys.json`,JSON.stringify(rows));console.log('Plan 36 Auth0 CLI: public connection keys verified');}finally{rmSync(home,{recursive:true,force:true});}
