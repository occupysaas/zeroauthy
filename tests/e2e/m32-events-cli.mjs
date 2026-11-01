import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile,appendFile,mkdir} from 'node:fs/promises';
import https from 'node:https';
import {work,credentials,webhook,webhookSecret,noSecrets,validate,receiver,management,failed,cleared,password,capture,until} from './m32-events-node.mjs';
const home=`${work}/private-cli-home`;
const env={PATH:process.env.PATH,HOME:home,HTTPS_PROXY:'http://127.0.0.1:9198',SSL_CERT_FILE:process.env.E2E_CERT,AUTH0_CLI_ANALYTICS:'false',AUTH0_CLI_AUTH_MODE:'env',AUTH0_DOMAIN:'sdk.e2e.test',AUTH0_CLIENT_ID:credentials.client,AUTH0_CLIENT_SECRET:credentials.secret};
async function run(cmd){const r=spawnSync(process.env.AUTH0_BIN,[...cmd,'--no-input','--no-color'],{env,encoding:'utf8',timeout:90000});assert.ifError(r.error);await appendFile(`${work}/cli.jsonl`,JSON.stringify({command:cmd.slice(0,3),stdout:r.stdout,stderr:r.stderr})+'\n');assert.equal(r.status,0,`${cmd.slice(0,3).join(' ')}: ${r.stderr}`);noSecrets(r.stdout,'CLI output');try{return JSON.parse(r.stdout)}catch{return r.stdout}}
async function cli(){
 await mkdir(home,{recursive:true,mode:0o700});
 const s=await run(['event-streams','create','--name','Plan32 CLI','--type','webhook','--subscriptions','user.updated','--configuration',JSON.stringify(webhook('/cli').configuration),'--json']);assert.ok(s.id);
 const listed=await run(['event-streams','list','--json']);assert.ok(listed.some(x=>x.id===s.id));assert.equal((await run(['event-streams','show',s.id,'--json'])).id,s.id);
 assert.equal((await run(['event-streams','update',s.id,'--name','Plan32 CLI updated','--json'])).name,'Plan32 CLI updated');
 await run(['event-streams','trigger',s.id,'--type','user.updated']);
 await receiver('control',{path:'/cli',status:500});const m=await management();const user=await m.users.create({connection:'Username-Password-Authentication',email:'cli-events@e2e.local',password});await m.users.update(user.user_id,{user_metadata:{cli:1}});await m.users.update(user.user_id,{user_metadata:{cli:2}});
 const failures=await failed(m,s.id,2);const list=await run(['event-streams','deliveries','list',s.id,'--type','user.updated','--json']);assert.equal(list.length,2);assert.ok(list.every(x=>failures.some(f=>f.id===x.id)));const detail=await run(['event-streams','deliveries','show',s.id,failures[0].id,'--json']);assert.equal(detail.id,failures[0].id);validate(detail.event);
 await receiver('control',{path:'/cli',status:200});await run(['event-streams','redeliver',s.id,failures[0].id]);await until(async()=>!(await m.eventStreams.deliveries.list(s.id)).data.some(row=>row.id===failures[0].id),'CLI single redelivery completes');
 // Native batch command must queue the remaining failed event.
 await run(['event-streams','redeliver-many',s.id,'--type','user.updated']);await cleared(m,s.id);
 await run(['event-streams','delete',s.id,'--force']);assert.ok(!(await run(['event-streams','list','--json'])).some(x=>x.id===s.id));
 // Leave one legitimate failed row so the privacy scan covers attempts/config/body.
 const audit=await m.eventStreams.create({name:'Plan32 audit failure',subscriptions:[{event_type:'user.updated'}],destination:webhook('/audit')});await receiver('control',{path:'/audit',status:404});await m.users.update(user.user_id,{user_metadata:{audit:true}});const rows=await failed(m,audit.id);assert.equal(rows[0].attempts.length,1);assert.equal(rows[0].attempts[0].error_message,'http_4xx: 404');await capture('audit failed delivery',rows);
 console.log('Plan32 Auth0 CLI 1.37.0: native CRUD/test/deliveries/single+batch redelivery; 404 fails once');
}
async function serve(){
 const statuses=new Map(),attempts=[];
 const server=https.createServer({key:await readFile(`${work}/key.pem`),cert:await readFile(`${work}/cert.pem`)},async(req,res)=>{
  try{
   if(req.method==='GET'&&req.url==='/'){res.writeHead(200,{'content-type':'application/json'}).end(JSON.stringify({attempts}));return;}
   const chunks=[];for await(const b of req)chunks.push(b);const body=Buffer.concat(chunks).toString();
   if(req.url==='/control'){const control=JSON.parse(body);statuses.set(control.path,control.status);res.writeHead(200,{'content-type':'application/json'}).end('{}');return;}
   assert.equal(req.method,'POST');assert.equal(req.headers['content-type'],'application/json');assert.equal(req.headers.authorization,`Bearer ${webhookSecret}`,'actual configured bearer authorization');const event=JSON.parse(body);validate(event);
   const attempt={path:req.url,status:statuses.get(req.url)??200,time:Date.now(),event,authorizationVerified:true};attempts.push(attempt);await appendFile(`${work}/receiver.jsonl`,JSON.stringify(attempt)+'\n');res.writeHead(attempt.status).end();
  }catch(e){console.error(e);res.writeHead(400).end();}
 });server.listen(9186,'127.0.0.1',()=>console.log('Plan32 local HTTPS receiver ready'));
}
if(process.argv[1]===import.meta.filename){await ({receiver:serve,cli}[process.argv[2]]??(()=>{throw Error('unknown CLI fixture mode')}))();}
