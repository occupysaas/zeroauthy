import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
const root=process.argv[2],packages=JSON.parse(fs.readFileSync(path.join(root,'registry.json')));
http.createServer((req,res)=>{
 const name=decodeURIComponent(new URL(req.url,'http://fixture').pathname.slice(1));
 if(packages[name]){const versions=packages[name];res.setHeader('content-type','application/json');res.end(JSON.stringify({name,versions,'dist-tags':{latest:Object.keys(versions).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true})).at(-1)}}));return;}
 if(!name.includes('/')&&name.endsWith('.tgz')&&fs.existsSync(path.join(root,name))){res.setHeader('content-type','application/octet-stream');fs.createReadStream(path.join(root,name)).pipe(res);return;}
 res.writeHead(404);res.end('offline fixture: package unavailable');
}).listen(9187,'127.0.0.1');
