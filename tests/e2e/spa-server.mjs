// tests/e2e/spa-server.mjs — serves the SPA over HTTPS on localhost:3443
// using the test certificate from run-m4.sh.
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';

const routes = {
  '/': ['spa/index.html', 'text/html; charset=utf-8'],
  '/app.js': ['spa/app.js', 'text/javascript'],
  '/auth0-spa-js.js': ['node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', 'text/javascript'],
};

const server = createServer(
  { cert: await readFile(process.env.E2E_CERT), key: await readFile(process.env.E2E_KEY) },
  async (req, res) => {
    const route = routes[new URL(req.url, 'https://localhost').pathname];
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    res.writeHead(200, { 'content-type': route[1], 'cache-control': 'no-store' });
    res.end(await readFile(new URL('./' + route[0], import.meta.url)));
  },
);
server.listen(3443, () => console.log('SPA on https://localhost:3443'));
