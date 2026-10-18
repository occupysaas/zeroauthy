// tests/e2e/spa-server.mjs — serves the SPA over HTTPS on localhost:3443
// using the test certificate from run-browser.sh.
import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';

if (!process.env.E2E_REACT_BUNDLE) {
  console.error('E2E_REACT_BUNDLE is required: path to the esbuild bundle of react/app.jsx (see run-browser.sh)');
  process.exit(1);
}

const routes = {
  '/': ['spa/index.html', 'text/html; charset=utf-8'],
  '/confirm/': ['spa/index.html', 'text/html; charset=utf-8'],
  '/strict/': ['spa/index.html', 'text/html; charset=utf-8'],
  '/app.js': ['spa/app.js', 'text/javascript'],
  '/auth0-spa-js.js': ['node_modules/@auth0/auth0-spa-js/dist/auth0-spa-js.production.js', 'text/javascript'],
  '/react/': ['react/index.html', 'text/html; charset=utf-8'],
  '/react/app.js': [process.env.E2E_REACT_BUNDLE, 'text/javascript'],
};

const server = createServer(
  { cert: await readFile(process.env.E2E_CERT), key: await readFile(process.env.E2E_KEY) },
  async (req, res) => {
    const path = new URL(req.url, 'https://localhost').pathname;
    // A landing page for redirects that a test reads from the request URL
    // (m10-par, m15-console): any page will do, so long as the browser finishes loading it.
    if (path === '/par-cb' || path === '/m15-callback') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      res.end('<!doctype html><title>callback</title>');
      return;
    }
    const route = routes[path];
    if (!route) {
      res.writeHead(404).end();
      return;
    }
    const file = route[0].startsWith('/') ? route[0] : new URL('./' + route[0], import.meta.url);
    res.writeHead(200, { 'content-type': route[1], 'cache-control': 'no-store' });
    res.end(await readFile(file));
  },
);
server.listen(3443, () => console.log('SPA on https://localhost:3443'));
