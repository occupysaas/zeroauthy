import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, readdir, cp, rm } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { load as parseYaml, dump as dumpYaml } from 'js-yaml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const e2e = path.join(root, 'tests/e2e');
const work = process.env.E2E_M20_WORK;
const format = process.env.E2E_M20_FORMAT;
const mode = process.env.E2E_M20_MODE;
assert.ok(['yaml', 'directory'].includes(format));
assert.ok(['generated', 'preserved'].includes(mode));
const secrets = ['e2e-cli-admin-secret-not-for-production', 'e2e-cli-target-admin-secret-not-for-production', 'e2e-cli-fixture-secret-not-for-production'];
const emailSecret = 'm21-deploy-private-provider-secret';
// Upstream provider credential the local mock accepts. It is written to the
// source by API and reinjected into staged imports from a private map only.
const upstreamSecret = 'm24-upstream-secret-not-for-production';
secrets.push(upstreamSecret);
const federation = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/fixtures/connections.json'), 'utf8'));
const federationCredentials = path.join(work, 'federation-credentials.json');
await writeFile(federationCredentials, JSON.stringify(Object.fromEntries(federation.map(c => [c.name, upstreamSecret]))), { mode: 0o600 });
const sourceConfig = { ...JSON.parse(await readFile(process.env.E2E_M20_CONFIG, 'utf8')), AUTH0_CLIENT_SECRET: secrets[0], AUTH0_EXPORT_IDENTIFIERS: false };
const targetConfig = { ...sourceConfig, AUTH0_DOMAIN: 'target.cli.e2e.test', AUTH0_CLIENT_ID: 'e2e-cli-target-admin', AUTH0_CLIENT_SECRET: secrets[1] };
const bin = path.join(e2e, 'node_modules/.bin/a0deploy');
const comparator = args => spawnSync('go', ['run', './tests/e2e/deploy-cli', ...args], { cwd: root, encoding: 'utf8' });
function checkedCompare(source, target) {
  const result = comparator(['compare', '--source', source, '--target', target, '--format', format, '--manifest', path.join(work, 'manifest.json')]);
  assert.ok(result.stdout, 'comparator produced no redacted report');
  return JSON.parse(result.stdout);
}
const version = spawnSync(bin, ['--version'], { encoding: 'utf8' });
assert.equal(version.status, 0); assert.equal(version.stdout.trim(), '9.1.0');
const manifest = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/manifest.json'), 'utf8'));
const excluded = JSON.parse(comparator(['exclusions', '--manifest', 'tests/e2e/deploy-cli/manifest.json']).stdout);
// These handlers require APIs outside the implemented roadmap. Their absence
// is reported explicitly, never counted as a successful migration.
const unavailable = manifest.resources.filter(entry => entry.status === 'tool-unsupported').map(entry => entry.name);
sourceConfig.AUTH0_EXCLUDED = excluded;
targetConfig.AUTH0_EXCLUDED = sourceConfig.AUTH0_EXCLUDED;
assert.ok(unavailable.every(name => excluded.includes(name)), 'manifest must explicitly exclude unavailable handlers');
await writeFile(path.join(work, 'manifest.json'), JSON.stringify(manifest), { mode: 0o600 });
for (const [name, config] of [['source', sourceConfig], ['target', targetConfig]]) await writeFile(path.join(work, `${name}.json`), JSON.stringify(config), { mode: 0o600 });
function deploy(command, config, input, expectedFailure) {
  const result = spawnSync(bin, [command, '--config_file', path.join(work, `${config}.json`), ...(command === 'export' ? ['--format', format, '--output_folder', input] : ['--input_file', input]), '--proxy_url', 'http://127.0.0.1:8098'], { cwd: e2e, encoding: 'utf8', env: { ...process.env, AUTH0_ALLOW_DELETE: 'false' } });
  // Tool failure logs can contain complete application payloads. Keep them in
  // restricted scratch storage and emit only operation/status to the console.
  if (expectedFailure) {
    assert.notEqual(result.status, 0, expectedFailure);
    const pattern = { 'unverified default import must fail': /custom_domain_not_ready|custom domain is not ready/i, 'uninjected federation import must fail': /client_secret/i }[expectedFailure] ?? /custom_client_ip_header|enum/i;
    assert.match(`${result.stdout}${result.stderr}`, pattern);
    return;
  }
  if (result.status !== 0) {
    let log = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    for (const secret of secrets) log = log.replaceAll(secret, '[redacted]');
    execFileSync('python3', ['-c', 'import sys; from pathlib import Path; p=Path(sys.argv[1]); p.write_text(sys.stdin.read()); p.chmod(0o600)', path.join(work, 'deploy-error.log')], { input: log });
    const diagnostic = log.split('\n').filter(line => /Status code:|\"message\":|Problem running command/.test(line)).join(' ');
    throw new Error(`pinned CLI ${command} failed (exit ${result.status}): ${diagnostic}`);
  }
}
async function exportTo(config, name) {
  const folder = path.join(work, name);
  await mkdir(folder, { recursive: true });
  deploy('export', config, folder);
  const exportPath = format === 'yaml' ? path.join(folder, 'tenant.yaml') : folder;
  await assertNoEmailSecrets(exportPath);
  return exportPath;
}
async function assertNoEmailSecrets(exportPath) {
  const files = format === 'yaml'
    ? [await readFile(exportPath, 'utf8')]
    : await Promise.all((await readdir(exportPath, { recursive: true })).map(name => readFile(path.join(exportPath, name), 'utf8').catch(() => '')));
  const joined = files.join('\n');
  for (const secret of proxySecrets) assert.equal(joined.includes(secret), false, 'deploy export contains a proxy secret');
  assert.equal(joined.includes(emailSecret), false, 'public deploy export contains provider credential');
  assert.equal(joined.includes(upstreamSecret), false, 'public deploy export contains a federation provider credential');
  assert.equal(joined.includes('********'), false, 'public deploy export contains a credential mask');
}
function request(config, method, route, body, token) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', port: config.AUTH0_DOMAIN === targetConfig.AUTH0_DOMAIN ? 8444 : 8443, servername: config.AUTH0_DOMAIN, path: route, method, headers: { host: config.AUTH0_DOMAIN, 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) } }, res => {
      let data = ''; res.setEncoding('utf8'); res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) { reject(new Error(`local ${method} ${route.split('?')[0]} returned ${res.statusCode}`)); return; }
        resolve(data ? JSON.parse(data) : null);
      });
    });
    req.on('error', reject); if (body !== undefined) req.write(JSON.stringify(body)); req.end();
  });
}
const tokens = new Map();
const proxySecrets = [];
async function api(config, method, route, body) {
  if (!tokens.has(config.AUTH0_DOMAIN)) {
    const token = await request(config, 'POST', '/oauth/token', { grant_type: 'client_credentials', client_id: config.AUTH0_CLIENT_ID, client_secret: config.AUTH0_CLIENT_SECRET, audience: `https://${config.AUTH0_DOMAIN}/api/v2/` });
    tokens.set(config.AUTH0_DOMAIN, token.access_token);
  }
  return request(config, method, `/api/v2/${route}`, body, tokens.get(config.AUTH0_DOMAIN));
}
async function inventory(config, expectFailure = false) {
  const rows = await api(config, 'GET', 'resource-servers');
  const file = path.join(work, 'inventory.json'); await writeFile(file, JSON.stringify(rows), { mode: 0o600 });
  const result = comparator(['preflight-inventory', '--input', file]);
  assert.equal(result.status === 0, !expectFailure, 'pre-export collision preflight result');
}

const templateBody = '<html><head>{% auth0:head %}</head><body><p>Exportable deploy template</p>{% auth0:widget %}</body></html>';
async function prove(config, domain) {
  const method = domain.verification.methods.find(m => m.name === 'txt');
  const response = await fetch('http://127.0.0.1:8064/proof', {method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({name:method.domain,value:method.record})});
  assert.equal(response.status,204);
  const verified = await api(config,'POST',`custom-domains/${domain.custom_domain_id}/verify`,{});
  assert.equal(verified.status,'ready');
  assert.ok(verified.cname_api_key, 'explicit verification must return the new proxy secret once');
  proxySecrets.push(verified.cname_api_key);
  assert.equal((await api(config,'GET',`custom-domains/${domain.custom_domain_id}`)).cname_api_key,undefined);
}
async function prepareImport(input, name, mutate = () => {}, { inject = true } = {}) {
  const folder=path.join(work,name);await mkdir(folder,{recursive:true});
  let destination;
  if(format==='yaml') {destination=path.join(folder,'tenant.yaml');await cp(path.dirname(input),folder,{recursive:true});}
  else {destination=folder;await cp(input,folder,{recursive:true});}
  const file=format==='yaml'?destination:path.join(destination,'custom-domains/custom-domains.json');
  const data=format==='yaml'?parseYaml(await readFile(file,'utf8')):JSON.parse(await readFile(file,'utf8'));
  const domains=format==='yaml'?data.customDomains:data;
  assert.ok(domains?.length,'migration must contain real custom-domain declarations');
  for(const d of domains) for(const key of ['custom_domain_id','verification','status','origin_domain_name','certificate','primary']) delete d[key];
  mutate(domains);
  await writeFile(file,format==='yaml'?dumpYaml(data):JSON.stringify(data),{mode:0o600});
  if(inject) await injectFederation(destination);
  return destination;
}
// Exports never carry provider credentials. The staged import receives them
// from the private credential map; a missing entry or script fails here.
async function injectFederation(destination, credentials = federationCredentials) {
  const prepared=path.join(work,'federation-prepared.json');
  const result=comparator(['prepare-federation','--source',destination,'--format',format,'--credentials',credentials,'--output',prepared]);
  if(result.status!==0) return false;
  const rows=JSON.parse(await readFile(prepared,'utf8'));await rm(prepared);
  if(format==='yaml') {const data=parseYaml(await readFile(destination,'utf8'));data.connections=rows;await writeFile(destination,dumpYaml(data),{mode:0o600});}
  else {const dir=path.join(destination,'connections');await rm(dir,{recursive:true,force:true});await mkdir(dir,{mode:0o700});for(const row of rows) await writeFile(path.join(dir,`${row.name}.json`),JSON.stringify(row),{mode:0o600});}
  return true;
}
// One provider login per migrated connection on the target: the hosted
// /authorize redirect, the mock provider's consent form, the federation
// callback and the downstream authorization-code + PKCE exchange.
async function federatedLogin(clientId, connection, subject, rbac=false) {
  const ports={'target.cli.e2e.test':8444,'idp.e2e.test':8446};const jar={};
  const send=(method,url,body)=>new Promise((resolve,reject)=>{const req=https.request({hostname:'127.0.0.1',port:ports[url.hostname],servername:url.hostname,path:url.pathname+url.search,method,headers:{host:url.hostname,...(jar[url.hostname]?{cookie:Object.entries(jar[url.hostname]).map(([k,v])=>`${k}=${v}`).join('; ')}:{}),...(body?{'content-type':'application/x-www-form-urlencoded'}:{})}},res=>{
    for(const c of res.headers['set-cookie']??[]){const [pair]=c.split(';');const i=pair.indexOf('=');(jar[url.hostname]??={})[pair.slice(0,i)]=pair.slice(i+1);}
    res.resume();res.on('end',()=>resolve(res));});req.on('error',reject);if(body)req.write(body);req.end();});
  const verifier=randomBytes(32).toString('base64url'),state=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex'),redirect='https://callback.e2e.test/';
  let url=new URL(`https://${targetConfig.AUTH0_DOMAIN}/authorize?${new URLSearchParams({client_id:clientId,redirect_uri:redirect,response_type:'code',scope:rbac?'openid profile email read:fixture write:fixture':'openid profile email',...(rbac?{audience:'https://fixture.cli.e2e.test'}:{}),state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',connection})}`);
  let method='GET',body,code;
  for(let hop=0;hop<12&&!code;hop++) {
    const res=await send(method,url,body);method='GET';body=undefined;
    if(res.statusCode>=300&&res.statusCode<400) {url=new URL(res.headers.location,url);if(url.href.startsWith(redirect)){assert.equal(url.searchParams.get('state'),state);code=url.searchParams.get('code');}continue;}
    assert.ok(res.statusCode===200&&url.hostname==='idp.e2e.test',`${connection}: unexpected ${res.statusCode} at ${url.hostname}${url.pathname}`);
    method='POST';body=new URLSearchParams({...Object.fromEntries(url.searchParams),subject,decision:'allow'}).toString();url=new URL(url.pathname,url);
  }
  assert.ok(code,`${connection}: no downstream authorization code`);
  const token=await request(targetConfig,'POST','/oauth/token',{grant_type:'authorization_code',client_id:clientId,code,code_verifier:verifier,redirect_uri:redirect});
  assert.ok(token.access_token);if(!rbac)assert.equal(token.scope,'openid profile email');
  const claims=JSON.parse(Buffer.from(token.id_token.split('.')[1],'base64url'));
  assert.equal(claims.nonce,nonce);assert.equal(claims.aud,clientId);assert.equal(claims.iss,`https://${targetConfig.AUTH0_DOMAIN}/`);
  return rbac?{sub:claims.sub,token}:claims.sub;
}

const sourcePath = format === 'yaml' ? path.join(work, 'source-export/tenant.yaml') : path.join(work, 'source-export');
if (process.env.E2E_M20_PHASE === 'prepare') {
  const registrySource = await readFile(path.join(e2e, 'node_modules/auth0-deploy-cli/lib/tools/auth0/handlers/index.js'), 'utf8');
  const body = registrySource.match(/const auth0ApiHandlers = \{([\s\S]*?)\n\};/);
  assert.ok(body);
  const names = [...body[1].matchAll(/^\s{4}(\w+),?\s*$/gm)].map(m => m[1]);
  if (body[1].includes('clientAuthCredentialsPre')) names.push('clientAuthCredentialsPre');
  const registryPath = path.join(work, 'registry.json'); await writeFile(registryPath, JSON.stringify([...new Set(names)].sort()));
  assert.equal(comparator(['validate-manifest', '--registry', registryPath, '--manifest', 'tests/e2e/deploy-cli/manifest.json']).status, 0);
  await inventory(sourceConfig);
  // Provider credentials are written from this isolated test process only.
  // They are never placed in a checked-in seed or recovered by GET/export.
  await api(sourceConfig, 'POST', 'emails/provider', { name: 'sendgrid', enabled: true, default_from_address: 'deploy@example.test', credentials: { api_key: emailSecret } });
  await api(sourceConfig, 'POST', 'email-templates', { template: 'verify_email', enabled: true, subject: 'Deploy verify', body: '<p>Verify {{ user.email | escape }}</p>' });
  const brandingFixture = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/fixtures/branding.json'), 'utf8'));
  const themeFixture = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/fixtures/theme.json'), 'utf8'));
  const promptFixture = JSON.parse(await readFile(path.join(e2e, 'deploy-cli/fixtures/prompts.json'), 'utf8'));
  await api(sourceConfig, 'PATCH', 'tenants/settings', { enabled_locales: ['en'] });
  await api(sourceConfig, 'PATCH', 'branding', brandingFixture);
  await api(sourceConfig, 'POST', 'branding/themes', themeFixture);
  const { customText, partials, ...settings } = promptFixture;
  await api(sourceConfig, 'PATCH', 'prompts', settings);
  for (const [lang,prompts] of Object.entries(customText)) for (const [prompt,text] of Object.entries(prompts)) await api(sourceConfig,'PUT',`prompts/${prompt}/custom-text/${lang}`,text);
  for (const [prompt,slots] of Object.entries(partials)) await api(sourceConfig,'PUT',`prompts/${prompt}/partials`,slots);
  await api(sourceConfig,'PUT','branding/templates/universal-login',{template:templateBody});
  const declarations=JSON.parse(await readFile(path.join(e2e,'deploy-cli/fixtures/custom-domains.json'),'utf8'));
  for(const declaration of declarations) {const d=await api(sourceConfig,'POST','custom-domains',declaration);await prove(sourceConfig,d);}
  await api(sourceConfig,'PATCH','custom-domains/default',{domain:declarations[0].domain});
  const publicProvider = await api(sourceConfig, 'GET', 'emails/provider');
  assert.equal(JSON.stringify(publicProvider).includes(emailSecret), false, 'provider read returned its private credential');
  assert.equal(JSON.stringify(publicProvider).includes('********'), false, 'provider read returned a credential mask');
  const collision = await api(sourceConfig, 'POST', 'resource-servers', { name: 'Auth0 Management API', identifier: 'https://collision.cli.e2e.test' });
  await inventory(sourceConfig, true);
  await api(sourceConfig, 'DELETE', `resource-servers/${collision.id}`);
  for (const c of federation) {
    const created = await api(sourceConfig, 'POST', 'connections', { ...c, enabled_clients: ['e2e-cli-browser'], options: { ...c.options, client_secret: upstreamSecret } });
    assert.equal(JSON.stringify(created).includes(upstreamSecret), false, 'connection create returned its provider credential');
  }
  const rbacAPI=(await api(sourceConfig,'GET','resource-servers')).find(r=>r.identifier==='https://fixture.cli.e2e.test');
  await api(sourceConfig,'PATCH',`resource-servers/${rbacAPI.id}`,{enforce_policies:true,token_dialect:'rfc9068_profile_authz',skip_consent_for_verifiable_first_party_clients:true});
  const roleDeclarations=JSON.parse(await readFile(path.join(e2e,'deploy-cli/fixtures/roles.json'),'utf8'));
  for(const {permissions,...declaration} of roleDeclarations){const role=await api(sourceConfig,'POST','roles',declaration);await api(sourceConfig,'POST',`roles/${role.id}/permissions`,{permissions});}
  const sourcePublicExport = await exportTo('source', 'source-export');
  await assertNoEmailSecrets(sourcePublicExport);
  assert.equal((await api(sourceConfig,'GET','branding/templates/universal-login')).body,templateBody);
  const exportConfig = format === 'yaml' ? parseYaml(await readFile(sourcePublicExport,'utf8')).branding : JSON.parse(await readFile(path.join(sourcePublicExport,'branding/templates/universal_login.json'),'utf8'));
  if(format==='yaml') assert.ok(exportConfig.templates?.length,'nonempty Universal Login template must export');
  else assert.ok(exportConfig.body,'directory template body reference must export');

  if (mode === 'preserved') {
    await writeFile(path.join(work, 'source.json'), JSON.stringify({ ...sourceConfig, AUTH0_EXPORT_IDENTIFIERS: true }), { mode: 0o600 });
    const bootstrapExport = await exportTo('source', 'bootstrap-export');
    await writeFile(path.join(work, 'source.json'), JSON.stringify(sourceConfig), { mode: 0o600 });
    const fixture = parseYaml(await readFile(path.join(e2e, 'deploy-cli/seed.yaml'), 'utf8'));
    const bootstrap = path.join(work, 'bootstrap.yaml');
    await writeFile(bootstrap, dumpYaml({ tenants: [fixture.tenants[1]] }), { mode: 0o600 });
    const credentials = path.join(work, 'credentials.json');
    await writeFile(credentials, JSON.stringify({ 'e2e-cli-fixture': secrets[2] }), { mode: 0o600 });
    const args = ['migration', 'bootstrap', '--config', 'tests/e2e/config.yaml', '--input', bootstrapExport, '--format', format, '--bootstrap-seed', bootstrap, '--credentials-file', credentials];
    for (const suffix of [['--check'], [], []]) {
      const result = spawnSync(process.env.E2E_M20_BINARY, [...args, ...suffix], { cwd: root, encoding: 'utf8', env: { ...process.env, ZEROAUTHY_SEED_MODE: 'create_only', ZEROAUTHY_STORAGE__DSN: process.env.E2E_M20_TARGET_DSN } });
      assert.equal(result.status, 0, `offline bootstrap failed: ${result.stderr?.replaceAll(secrets[2], '[redacted]')}`);
    }
  }
  process.exit(0);
}
const baseline = checkedCompare(sourcePath, sourcePath);
assert.equal(baseline.equivalent, true, JSON.stringify(baseline)); assert.ok(baseline.counts.every(row => row.source > 0));
const exportClients = async config => (await api(config, 'GET', 'clients')).filter(c => c.name === 'E2E deploy fixture');
const original = (await exportClients(sourceConfig))[0];
const toolBefore = await api(targetConfig, 'GET', `clients/${targetConfig.AUTH0_CLIENT_ID}`);
// This target-side private configuration is the explicit reinjection point.
// The subsequent CLI import omits credentials and its PATCH must preserve it.
  await api(targetConfig, 'POST', 'emails/provider', { name: 'sendgrid', enabled: false, default_from_address: 'target-before-import@example.test', credentials: { api_key: emailSecret } });
assertPrivateEmailCredential();
const missing=path.join(work,'federation-missing.json');
await writeFile(missing,JSON.stringify({[federation[0].name]:upstreamSecret}),{mode:0o600});
assert.equal(await injectFederation(await prepareImport(sourcePath,'federation-missing',d=>{for(const x of d)x.is_default=false;},{inject:false}),missing),false,'missing provider-secret injection was accepted');
deploy('import','target',await prepareImport(sourcePath,'federation-uninjected',d=>{for(const x of d)x.is_default=false;},{inject:false}),'uninjected federation import must fail');
assert.equal((await api(targetConfig,'GET','connections?strategy=windowslive')).length,0,'uninjected import created a connection without credentials');
const finalImport=await prepareImport(sourcePath,'final-import');
deploy('import','target',finalImport,'unverified default import must fail');
assert.equal((await api(targetConfig,'GET','custom-domains/default')).domain,'target.cli.e2e.test');
const declarationsImport=await prepareImport(sourcePath,'declarations-import',domains=>{for(const d of domains)d.is_default=false;});
deploy('import','target',declarationsImport);
const pending=await api(targetConfig,'GET','custom-domains');
assert.ok(pending.length>0);for(const d of pending) {assert.equal(d.status,'pending_verification');await prove(targetConfig,d);}
deploy('import', 'target', finalImport);
function assertPrivateEmailCredential() {
  const result = spawnSync('go', ['test', './tests/e2e/deploy-cli', '-run', '^TestE2EPrivateEmailProviderCredentialAfterImport$', '-count=1'], { cwd: root, encoding: 'utf8', env: { ...process.env, E2E_EMAIL_PRIVATE_SECRET: emailSecret } });
  assert.equal(result.status, 0, `private email credential did not survive import: ${(result.stdout + result.stderr).replaceAll(emailSecret, '[redacted]')}`);
}
assertPrivateEmailCredential();
let targetPath = await exportTo('target', 'target-first');
assert.equal(checkedCompare(sourcePath, targetPath).equivalent, true, 'first round trip differs');
const imported = (await exportClients(targetConfig))[0];
// Every migrated connection must log in through its provider on the target,
// with canonical identities keyed by the imported connection names.
const browser=(await api(targetConfig,'GET','clients')).find(c=>c.name==='E2E deploy browser');
assert.ok(browser,'browser application was not migrated');
const expectedUsers={'google-oauth2':['deploy-google','google-oauth2|deploy-google'],'deploy-oauth':['deploy-oauth-user','oauth2|deploy-oauth|deploy-oauth-user'],'deploy-oidc':['deploy-oidc-user',null],'microsoft-personal':['outlook','windowslive|Sub-outlook'],'microsoft-directory':['work','waad|microsoft-directory|aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'],'microsoft-organizations':['work','waad|microsoft-organizations|11111111-1111-4111-8111-111111111111:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa']};
assert.deepEqual(Object.keys(expectedUsers).sort(),federation.map(c=>c.name).sort());
for(const [connection,[subject,want]] of Object.entries(expectedUsers)) {
  const sub=await federatedLogin(browser.client_id,connection,subject);
  if(want) assert.equal(sub,want,`${connection} identity format changed through migration`);
  assert.equal(await federatedLogin(browser.client_id,connection,subject),sub,`${connection} repeat login changed ownership`);
  const user=await api(targetConfig,'GET',`users/${encodeURIComponent(sub)}`);
  assert.equal(user.identities.length,1);assert.equal(user.identities[0].connection,connection);assert.equal(user.identities[0].access_token,undefined);
}
// Assign an actual migrated tenant role after creating a real federated user.
const migratedRole=(await api(targetConfig,'GET','roles')).find(r=>r.name==='Deploy Reader');
assert.ok(migratedRole,'role definition was lost during deployment');
const migratedPermissions=await api(targetConfig,'GET',`roles/${migratedRole.id}/permissions`);
assert.deepEqual(migratedPermissions.map(p=>[p.resource_server_identifier,p.permission_name]),[['https://fixture.cli.e2e.test','read:fixture']]);
const rbacSubject='google-oauth2|deploy-google';
await api(targetConfig,'POST',`users/${encodeURIComponent(rbacSubject)}/roles`,{roles:[migratedRole.id]});
const rbacLogin=await federatedLogin(browser.client_id,'google-oauth2','deploy-google',true);
const rbacClaims=JSON.parse(Buffer.from(rbacLogin.token.access_token.split('.')[1],'base64url'));
assert.equal(rbacLogin.sub,rbacSubject);assert.ok(rbacLogin.token.scope.split(' ').includes('read:fixture'));assert.ok(!rbacLogin.token.scope.split(' ').includes('write:fixture'));
assert.deepEqual(rbacClaims.permissions,['read:fixture']);assert.equal(rbacClaims.client_id,browser.client_id);assert.equal(JSON.parse(Buffer.from(rbacLogin.token.access_token.split('.')[0],'base64url')).typ,'at+jwt');
console.log('Plan 26 deploy: tenant role/API fields and post-import federated RBAC code exchange passed');
console.log(`Plan 25 deploy: ${federation.length} federated connections (5 strategies) imported with explicit secret reinjection; missing/uninjected imports rejected; first and repeat provider logins passed`);
assert.equal(imported.client_id === original.client_id, mode === 'preserved');
assert.ok((imported.client_secret === original.client_secret) === (mode === 'preserved'), 'credential preservation mode mismatch');
assert.ok(imported.client_secret);
const toolAfter = await api(targetConfig, 'GET', `clients/${targetConfig.AUTH0_CLIENT_ID}`);
assert.ok(JSON.stringify(toolAfter) === JSON.stringify(toolBefore), 'deployment credential client was changed');
// Inventory the unrelated destination resource before and after import, then
// delete only this test-created record before comparing migration resources.
const extra = await api(targetConfig, 'POST', 'clients', { name: 'Target-only application', app_type: 'spa', token_endpoint_auth_method: 'none', grant_types: ['authorization_code'] });
const extraBefore = await api(targetConfig, 'GET', `clients/${extra.client_id}`);
deploy('import', 'target', finalImport);
assert.ok(JSON.stringify(await api(targetConfig, 'GET', `clients/${extra.client_id}`)) === JSON.stringify(extraBefore), 'deletion-disabled import changed target-only resource');
await api(targetConfig, 'DELETE', `clients/${extra.client_id}`);
const repeated = (await exportClients(targetConfig))[0];
assert.equal(repeated.client_id, imported.client_id); assert.ok(repeated.client_secret === imported.client_secret, 'repeat import changed credential');
targetPath = await exportTo('target', 'target-repeat');
assert.equal(checkedCompare(sourcePath, targetPath).equivalent, true, 'repeat import differs');
await api(sourceConfig,'PATCH','branding',{colors:{primary:'#654321'}});
const changedBranding=await exportTo('source','source-branding-changed');
assert.equal(checkedCompare(changedBranding,targetPath).equivalent,false,'negative branding change escaped comparator');
await api(sourceConfig,'PATCH','branding',{colors:{primary:'#123456'}});
const currentTheme=await api(sourceConfig,'GET','branding/themes/default');
await api(sourceConfig,'PATCH',`branding/themes/${currentTheme.themeId}`,{colors:{primary_button:'#654321'}});
const changedTheme=await exportTo('source','source-theme-changed');
assert.equal(checkedCompare(changedTheme,targetPath).equivalent,false,'negative theme change escaped comparator');
await api(sourceConfig,'PATCH',`branding/themes/${currentTheme.themeId}`,{colors:{primary_button:'#123456'}});
await api(sourceConfig,'PUT','prompts/login-id/custom-text/en',{'login-id':{title:'Changed deploy identify'}});
const changedText=await exportTo('source','source-text-changed');
assert.equal(checkedCompare(changedText,targetPath).equivalent,false,'negative text change escaped comparator');
await api(sourceConfig,'PUT','prompts/login-id/custom-text/en',{'login-id':{title:'Deploy identify'}});
await api(sourceConfig,'PUT','prompts/login-id/partials',{'login-id':{'form-footer-start':'<p>Changed footer</p>'}});
const changedPartials=await exportTo('source','source-partials-changed');
assert.equal(checkedCompare(changedPartials,targetPath).equivalent,false,'negative partial change escaped comparator');
await api(sourceConfig,'PUT','prompts/login-id/partials',{'login-id':{'form-footer-start':'<p>Deploy footer</p>'}});
await api(sourceConfig, 'PATCH', 'tenants/settings', { friendly_name: 'Updated deploy fixture' });
const grants = await api(sourceConfig, 'GET', 'client-grants');
const grant = grants.find(g => g.client_id === original.client_id);
await api(sourceConfig, 'PATCH', `client-grants/${grant.id}`, { scope: ['read:fixture'] });
const updated = await exportTo('source', 'source-updated');
assert.equal(checkedCompare(updated, targetPath).equivalent, false, 'negative scope/setting change escaped comparator');
await api(sourceConfig, 'PATCH', 'emails/provider', { enabled: false });
await api(sourceConfig, 'PATCH', 'email-templates/verify_email', { subject: 'Changed deploy verify' });
const changedEmail = await exportTo('source', 'source-email-updated');
assert.equal(checkedCompare(changedEmail, targetPath).equivalent, false, 'negative provider/template change escaped comparator');
deploy('import', 'target', await prepareImport(changedEmail,'email-import'));
assertPrivateEmailCredential();
targetPath = await exportTo('target', 'target-email-updated');
assert.equal(checkedCompare(changedEmail, targetPath).equivalent, true, 'email resource update differs');
const targetProvider = await api(targetConfig, 'GET', 'emails/provider');
assert.equal(JSON.stringify(targetProvider).includes(emailSecret), false, 'target provider read returned its private credential');
assert.equal(JSON.stringify(targetProvider).includes('********'), false, 'target provider read returned a credential mask');
deploy('import', 'target', await prepareImport(updated,'updated-import'));
targetPath = await exportTo('target', 'target-updated');
const report = checkedCompare(updated, targetPath);
assert.equal(report.equivalent, true, 'updated round trip differs');
assert.equal((await api(targetConfig, 'GET', 'tenants/settings')).friendly_name, 'Updated deploy fixture');
const token = await request(targetConfig, 'POST', '/oauth/token', { grant_type: 'client_credentials', client_id: imported.client_id, client_secret: imported.client_secret, audience: 'https://fixture.cli.e2e.test', scope: 'read:fixture' });
assert.ok(token.access_token); assert.equal(token.scope, 'read:fixture');
const claims = JSON.parse(Buffer.from(token.access_token.split('.')[1], 'base64url'));
assert.equal(claims.iss, `https://${targetConfig.AUTH0_DOMAIN}/`); assert.ok([claims.aud].flat().includes('https://fixture.cli.e2e.test'));
await api(sourceConfig,'PATCH','emails/provider',{enabled:true});
await api(sourceConfig,'PATCH','email-templates/verify_email',{subject:'Deploy verify'});
assert.equal(checkedCompare(await exportTo('source','source-domain-baseline'),targetPath).equivalent,true,'domain negative baseline differs');
// Compare actual exports after mutating each writable migration setting.
const sourceDomain=(await api(sourceConfig,'GET','custom-domains'))[0];
for(const [field,value] of Object.entries({custom_client_ip_header:'true-client-ip',domain_metadata:{region:'changed'},relying_party_identifier:'login.migrate.e2e.test'})) {
 await api(sourceConfig,'PATCH',`custom-domains/${sourceDomain.custom_domain_id}`,{[field]:value});
 const changed=await exportTo('source',`source-domain-${field}`);
 assert.equal(checkedCompare(changed,targetPath).equivalent,false,`changed ${field} escaped comparator`);
 await api(sourceConfig,'PATCH',`custom-domains/${sourceDomain.custom_domain_id}`,{[field]:sourceDomain[field]});
}
await api(sourceConfig,'PUT','branding/templates/universal-login',{template:templateBody.replace('Exportable','Changed')});
assert.equal(checkedCompare(await exportTo('source','source-template-changed'),targetPath).equivalent,false,'changed Universal Login body escaped comparator');
await api(sourceConfig,'PUT','branding/templates/universal-login',{template:templateBody});
// CLI only applies true defaults. A canonical source requires explicit reset.
await api(sourceConfig,'PATCH','custom-domains/default',{domain:sourceConfig.AUTH0_DOMAIN});
const canonicalSource=await exportTo('source','canonical-source');
deploy('import','target',await prepareImport(canonicalSource,'canonical-import'));
const uncleared=await exportTo('target','canonical-uncleared');
assert.equal(checkedCompare(canonicalSource,uncleared).equivalent,false,'CLI silently cleared canonical default');
await api(targetConfig,'PATCH','custom-domains/default',{domain:targetConfig.AUTH0_DOMAIN});
deploy('import','target',await prepareImport(canonicalSource,'canonical-prepared'));
assert.equal(checkedCompare(canonicalSource,await exportTo('target','canonical-cleared')).equivalent,true,'explicit canonical preparation differs');
for(const header of ['x-azure-clientip','']) {
 const rejected=await prepareImport(canonicalSource,`header-${header||'empty'}`,domains=>{domains[0].custom_client_ip_header=header;});
 deploy('import','target',rejected,`pinned CLI must reject API-only header ${header||'empty'}`);
 const row=(await api(sourceConfig,'GET','custom-domains'))[0];
 await api(sourceConfig,'PATCH',`custom-domains/${row.custom_domain_id}`,{custom_client_ip_header:header});
 assert.equal((await api(sourceConfig,'GET',`custom-domains/${row.custom_domain_id}`)).custom_client_ip_header,header);
}
console.log('Plan 23 deploy: staged DNS/API proof, canonical reset and template body round trips passed; x-azure-clientip/empty header tool-unavailable (actual CLI rejection); ACUL excluded.');
process.stdout.write(`Plan 20 deploy-cli: version=9.1.0 format=${format} mode=${mode} lane=local import=passed repeat=passed credentials=passed update=passed targetOnly=passed negative=detected runtime=passed counts=${JSON.stringify(report.counts)}\n`);
