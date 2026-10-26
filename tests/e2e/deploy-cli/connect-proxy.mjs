// Isolated deployments need independent global hostname registries.
import net from 'node:net';
import http from 'node:http';
const server = http.createServer((_req, res) => res.writeHead(405).end());
server.on('connect', (req, client, head) => {
 const [host, port] = String(req.url).split(':');
 if (!['cli.e2e.test','target.cli.e2e.test'].includes(host) || port !== '443') {client.end('HTTP/1.1 403 Forbidden\r\n\r\n');return;}
 const upstream=net.connect({host:'127.0.0.1',port:host==='target.cli.e2e.test'?8444:8443},()=>{
  client.write('HTTP/1.1 200 Connection Established\r\n\r\n');if(head.length)upstream.write(head);upstream.pipe(client);client.pipe(upstream);
 });
 const close=()=>{upstream.destroy();client.destroy();};upstream.on('error',close);client.on('error',close);
});
server.listen(8098,'127.0.0.1');
