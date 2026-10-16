// A stand-in legacy user database for the custom database E2E tests. It is a
// small HTTP service holding users in memory and counting how often each
// operation is called, so tests can tell whether zeroauthy went back to it.
import { createServer } from 'node:http';
import { createHash, timingSafeEqual } from 'node:crypto';

const port = Number(process.env.LEGACY_PORT || 8099);
const token = process.env.LEGACY_TOKEN;
if (!token) throw new Error('LEGACY_TOKEN is required');

const digest = (s) => createHash('sha256').update(String(s)).digest();
const sameSecret = (a, b) => timingSafeEqual(digest(a), digest(b));

const users = new Map();
const stats = { login: 0, get_user: 0, create: 0, password: 0 };
const key = (email) => String(email).toLowerCase();
const profile = (u) => ({ user_id: u.id, email: u.email, name: u.name, email_verified: true });

function addUser(email, password, id, name) {
  users.set(key(email), { id, email, name, passwordDigest: digest(password) });
}
addUser('legacy-user@e2e.local', 'Legacy-Password-1', 'L-1001', 'Legacy User');
// A second user for the import-mode connection: stored user IDs are tenant-wide
// (auth0|<user_id>), so two connections cannot both hold L-1001.
addUser('import-user@e2e.local', 'Import-Password-1', 'L-1002', 'Import User');
let nextId = 2000;

async function readJSON(req) {
  let raw = '';
  for await (const chunk of req) raw += chunk;
  return raw ? JSON.parse(raw) : {};
}

const server = createServer(async (req, res) => {
  const send = (status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body ?? {}));
  };
  try {
    if (!sameSecret(req.headers.authorization || '', 'Bearer ' + token)) return send(401, { error: 'unauthorized' });
    const url = new URL(req.url, 'http://legacy.local');
    const route = `${req.method} ${url.pathname}`;

    if (route === 'GET /stats') return send(200, stats);
    if (route === 'POST /login') {
      stats.login++;
      const { email, password } = await readJSON(req);
      const u = users.get(key(email));
      if (!u || !timingSafeEqual(digest(password), u.passwordDigest)) return send(401, { error: 'bad credentials' });
      return send(200, profile(u));
    }
    if (route === 'GET /users') {
      stats.get_user++;
      const u = users.get(key(url.searchParams.get('email')));
      return u ? send(200, profile(u)) : send(404, { error: 'no such user' });
    }
    if (route === 'POST /users') {
      stats.create++;
      const { email, password, name } = await readJSON(req);
      if (users.has(key(email))) return send(409, { error: 'exists' });
      addUser(email, password, `L-${nextId++}`, name || email);
      return send(201, profile(users.get(key(email))));
    }
    if (route === 'POST /password') {
      stats.password++;
      const { email, password } = await readJSON(req);
      const u = users.get(key(email));
      if (!u) return send(404, { error: 'no such user' });
      u.passwordDigest = digest(password);
      return send(200, { changed: true });
    }
    return send(404, { error: 'not found' });
  } catch (err) {
    return send(400, { error: String(err.message || err) });
  }
});
server.listen(port, '127.0.0.1', () => console.log(`legacy store on 127.0.0.1:${port}`));
