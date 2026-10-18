// tests/e2e/connect-proxy.mjs: an HTTPS (CONNECT) proxy that sends every
// *.e2e.test:443 tunnel to zeroauthy on 127.0.0.1:8443, so that clients
// which only speak to https://<domain> (auth0-cli) reach a test tenant.
// Anything else is refused.
import net from 'node:net';
import http from 'node:http';

const port = Number(process.env.PROXY_PORT ?? 8098);
const target = { host: '127.0.0.1', port: Number(process.env.TARGET_PORT ?? 8443) };

const server = http.createServer((_req, res) => {
  res.writeHead(405).end();
});
server.on('connect', (req, client, head) => {
  const [host, p] = String(req.url).split(':');
  if (!host.endsWith('.e2e.test') || p !== '443') {
    client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    return;
  }
  const upstream = net.connect(target, () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length) upstream.write(head);
    upstream.pipe(client);
    client.pipe(upstream);
  });
  const close = () => {
    upstream.destroy();
    client.destroy();
  };
  upstream.on('error', close);
  client.on('error', close);
});
server.listen(port, '127.0.0.1', () => console.log(`connect proxy on 127.0.0.1:${port} -> ${target.host}:${target.port}`));
