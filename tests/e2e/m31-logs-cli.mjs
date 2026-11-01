import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {mkdir,writeFile,appendFile,readFile} from 'node:fs/promises';
import http from 'node:http';
import {state,saveState,work,credentials,marker,noSecrets,until,secrets} from './m31-node-auth0.mjs';
const home=`${work}/private-cli-home`;
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:credentials.client,AUTH0_CLIENT_SECRET:credentials.secret};
const args=cmd=>[...cmd,'--no-input','--no-color'];
async function run(cmd,status=0){const r=spawnSync(process.env.AUTH0_BIN,args(cmd),{env,encoding:'utf8',timeout:60000});assert.ok(!r.error,String(r.error));await appendFile(`${work}/cli.jsonl`,JSON.stringify({command:cmd.slice(0,4),stdout:r.stdout,stderr:r.stderr})+'\n');assert.equal(r.status,status,`${cmd.slice(0,3).join(' ')}: ${r.stderr}`);noSecrets(r.stdout,'CLI');try{return JSON.parse(r.stdout)}catch{return r.stdout}}
export async function startTail(){await mkdir(home,{recursive:true,mode:0o700});const p=spawn(process.env.AUTH0_BIN,args(['logs','tail','--number','100','--json-compact']),{env,stdio:['ignore','pipe','pipe']});let stdout='',stderr='';const ids=()=>stdout.trim().split('\n').filter(Boolean).flatMap(line=>{try{return [JSON.parse(line).log_id]}catch{return []}});p.stdout.on('data',b=>stdout+=b);p.stderr.on('data',b=>stderr+=b);const exited=new Promise(resolve=>p.once('close',(code,signal)=>resolve({code,signal})));p.on('error',e=>stderr+=String(e));return {async contains(id){return until(()=>{if(ids().includes(id)){assert.equal(ids().filter(x=>x===id).length,1,'CLI tail event occurs once');return true;}if(p.exitCode!==null)throw Error(`CLI tail exited before browser event: ${stderr.trim()}`);return false;},'CLI tail browser failure',45000);},async close(){p.kill('SIGINT');const timer=setTimeout(()=>p.kill('SIGKILL'),3000);await exited;clearTimeout(timer);await writeFile(`${work}/cli-tail.jsonl`,stdout);await writeFile(`${work}/cli-tail.stderr`,stderr);noSecrets(stdout,'CLI tail');assert.equal(new Set(ids()).size,ids().length,'CLI tail does not repeat events');}};}
async function create(){
 await mkdir(home,{recursive:true,mode:0o700});const f=await state();f.streams=[];
 for(const format of ['JSONLINES','JSONARRAY','JSONOBJECT']){
  const s=await run(['logs','streams','create','http','--name',`Plan31 ${format}`,'--endpoint',`http://127.0.0.1:9186/${format}`,'--type','application/json','--format',format,'--filters',JSON.stringify([{type:'category',name:'auth.login.success'},{type:'category',name:'auth.login.fail'},{type:'category',name:'management.success'},{type:'category',name:'auth.token_exchange.success'}]),'--pii-config',JSON.stringify({log_fields:['email'],method:'mask',algorithm:'xxhash'}),'--json']);
  assert.ok(s.id);assert.equal(s.sink.httpContentFormat,format);f.streams.push({id:s.id,format});
  const updated=await run(['logs','streams','update','http',s.id,'--name',`Plan31 updated ${format}`,'--json']);assert.equal(updated.name,`Plan31 updated ${format}`);
 }
 const all=await run(['logs','streams','list','--json']);assert.ok(f.streams.every(s=>all.some(x=>x.id===s.id)));await saveState(f);console.log('Plan31 Auth0 CLI 1.37.0: HTTP streams create/list/update in all three formats');
}
async function verify(){
 const f=await state();let filteredFailure;
 try{const rows=await run(['logs','list','--filter',`type:f AND user_id:"${f.user}"`,'--number','100','--json']);assert.ok(rows.some(x=>x.log_id===f.failure));assert.ok(rows.every(x=>x.type==='f'&&x.user_id===f.user));}catch(e){filteredFailure=e.message;}
 const all=await run(['logs','list','--number','100','--json']);assert.ok(all.some(x=>x.log_id===f.failure),'unfiltered CLI list contains browser failure');
 for(const s of f.streams)await run(['logs','streams','delete',s.id,'--force']);
 const left=await run(['logs','streams','list','--json']);assert.ok(f.streams.every(s=>!left.some(x=>x.id===s.id)));
 await writeFile(`${work}/cli-status.json`,JSON.stringify({version:'1.37.0',unfilteredList:'passed',streamCRUD:'passed',filteredList:filteredFailure??'passed',tail:await readFile(`${work}/cli-tail.stderr`,'utf8')},null,2));
 console.log('Plan31 Auth0 CLI: unfiltered list contains browser event; HTTP streams delete/list passed');
 if(filteredFailure)throw Error(filteredFailure);
 console.log('Plan31 Auth0 CLI: filtered logs agree with browser event');
}
function receiver(){
 let fail=false;const attempts=[];
 const server=http.createServer(async(req,res)=>{
  if(req.method==='GET'&&req.url==='/'){res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({attempts}));return;}
  const chunks=[];for await(const b of req)chunks.push(b);const body=Buffer.concat(chunks).toString();
  if(req.url==='/control'){fail=JSON.parse(body).fail;res.writeHead(200,{'content-type':'application/json'}).end('{}');return;}
  try{
   assert.equal(req.method,'POST');assert.equal(req.headers['content-type'],'application/json');let items;
   if(req.url==='/JSONARRAY'){items=JSON.parse(body);assert.ok(Array.isArray(items));}
   else if(req.url==='/JSONOBJECT'){const item=JSON.parse(body);assert.ok(!Array.isArray(item));items=[item];}
   else {assert.equal(req.url,'/JSONLINES');items=body.trim().split('\n').map(line=>JSON.parse(line));}
   assert.ok(items.length);for(const item of items){assert.match(item.log_id,/^\d{56}$/);assert.equal(typeof item.data,'object');noSecrets(item,'receiver body');}
   const attempt={path:req.url,status:fail?503:200,body,items};attempts.push(attempt);await appendFile(`${work}/receiver.jsonl`,JSON.stringify(attempt)+'\n');res.writeHead(attempt.status).end();
  }catch(e){console.error(e);res.writeHead(400).end();}
 });server.listen(9186,'127.0.0.1',()=>console.log('Plan31 local receiver ready'));
}
async function audit(){
 const names=['acceptance.json','cli-status.json','migrate.log','log-rows.jsonl','execution-rows.jsonl','monitoring.jsonl','browser-monitoring.jsonl','browser-console.jsonl','receiver.jsonl','receiver.log','server.log','server-restart.log','cli.jsonl','cli-tail.jsonl','cli-tail.stderr','bootstrap.stderr','proxy.log'];
 let bytes=0;for(const name of names){const value=await readFile(`${work}/${name}`,'utf8');bytes+=value.length;noSecrets(value,`artifact ${name}`);}
 const rows=await readFile(`${work}/log-rows.jsonl`,'utf8');assert.ok(rows.includes(marker),'stored logs redact nested request metadata');
 const executions=await readFile(`${work}/execution-rows.jsonl`,'utf8');assert.ok(executions.includes(marker));assert.ok(executions.includes('plan31-action-console'));
 const server=(await readFile(`${work}/server.log`,'utf8'))+(await readFile(`${work}/server-restart.log`,'utf8'));assert.ok(server.includes('plan31-customdb-console'));assert.ok(server.includes(marker),'custom database printed credentials masked');assert.ok(!server.includes('setup_url'),'startup bootstrap email must remain unset');
 const excluded=['logs.db (users, credentials, metadata, encrypted Action/stream secrets; audited log/execution rows exported separately)','private-state.json','private-cli-home/','config.yaml','seed.yaml','key.pem','master.key','operator-setup.txt (0600 CLI bootstrap link)','actions-cache/','zeroauthy binary','playwright-results/ (trace disabled; may contain failure-only credential-form screenshot)'];
 await writeFile(`${work}/privacy-audit.json`,JSON.stringify({passed:true,representativeSecrets:secrets.length,auditedSinks:names,bytes,excluded,scope:'Logging/monitoring sinks only; credential provisioning and application user storage are intentionally private fixture inputs.'},null,2));console.log(`Plan31 privacy: ${names.length} logging/monitoring artifacts (${bytes} bytes), ${secrets.length} representative secrets absent`);
}
if(process.argv[1]===import.meta.filename){await ({create,verify,receiver,audit}[process.argv[2]]??(()=>{throw Error('unknown CLI fixture mode')}))();}
