// zeroauthy custom database script runner. One process serves one tenant.
// Protocol: one JSON request per stdin line, one JSON response per stdout line;
// script console output goes to stderr as JSON lines.
//
// The host starts this file with an empty environment and Node's permission
// model (--permission, read access only to this directory and the optional
// modules directory). The vm context below is a convenience, not a security
// boundary: the process boundary is.
import vm from 'node:vm';
import readline from 'node:readline';
import { createRequire, builtinModules } from 'node:module';
import { createHash } from 'node:crypto';
import path from 'node:path';

const modulesDir = process.argv[2] || '';
const denied = new Set(['child_process', 'cluster', 'worker_threads', 'inspector', 'vm', 'v8', 'module', 'repl', 'wasi', 'trace_events']);
const hostRequire = createRequire(modulesDir ? path.join(modulesDir, 'noop.js') : import.meta.url);

function sandboxRequire(name) {
  const bare = String(name).replace(/^node:/, '');
  if (denied.has(bare)) throw new Error(`module "${bare}" is not available to custom database scripts`);
  if (builtinModules.includes(bare)) return hostRequire('node:' + bare);
  if (!modulesDir) throw new Error(`module "${bare}" is not installed (set custom_db.modules_dir)`);
  return hostRequire(String(name));
}

class WrongUsernameOrPasswordError extends Error {
  constructor(identifier, message) { super(message || 'Wrong email or password.'); this.name = 'WrongUsernameOrPasswordError'; this.identifier = identifier ?? null; }
}
class ValidationError extends Error {
  constructor(code, message) { super(message || code); this.name = 'ValidationError'; this.code = code; }
}
class UnauthorizedError extends Error {
  constructor(message) { super(message); this.name = 'UnauthorizedError'; }
}

const contexts = new Map(); // conn + config hash → vm context
const compiled = new Map(); // conn + config hash + source hash → function

function contextFor(conn, config) {
  const key = conn + ':' + createHash('sha256').update(JSON.stringify(config ?? {})).digest('hex');
  let ctx = contexts.get(key);
  if (!ctx) {
    const logger = (level) => (...a) => log(conn, level, a);
    const sandbox = {
      global: {},
      WrongUsernameOrPasswordError, ValidationError, UnauthorizedError,
      require: sandboxRequire,
      console: { log: logger('info'), info: logger('info'), warn: logger('warn'), error: logger('error'), debug: logger('debug') },
      setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate,
      Buffer, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, AbortSignal,
      fetch, Headers, Request, Response, crypto: globalThis.crypto,
      // The real process: its env is empty and --permission guards the rest.
      process,
    };
    // Non-writable so `configuration = …` cannot replace it for later calls.
    Object.defineProperty(sandbox, 'configuration', {
      value: Object.freeze({ ...(config ?? {}) }), writable: false, enumerable: true, configurable: false,
    });
    ctx = vm.createContext(sandbox, { name: 'customdb:' + conn });
    contexts.set(key, ctx);
  }
  return { key, ctx };
}

const aliases = {
  login: ['login'], get_user: ['getUser', 'getByEmail', 'get_user'], create: ['create'],
  verify: ['verify'], change_password: ['changePassword', 'change_password'],
  delete: ['remove', 'deleteUser', 'del'], change_email: ['changeEmail', 'change_email'],
};

function compile(req) {
  const { key, ctx } = contextFor(req.conn, req.config);
  const ckey = key + ':' + req.hash;
  let fn = compiled.get(ckey);
  if (fn) return fn;
  const filename = `${req.name}.js`;
  try {
    // Auth0 scripts are one function; read as an expression it evaluates to that function.
    fn = new vm.Script('(' + req.source.trim().replace(/;\s*$/, '') + '\n)', { filename }).runInContext(ctx, { timeout: 1000 });
  } catch {
    new vm.Script(req.source, { filename }).runInContext(ctx, { timeout: 1000 });
    fn = (aliases[req.name] || []).map((n) => ctx[n]).find((f) => typeof f === 'function');
  }
  if (typeof fn !== 'function') throw new Error(`the ${req.name} script does not define a function`);
  compiled.set(ckey, fn);
  return fn;
}

function toWireError(err) {
  const name = err && err.name;
  if (name === 'WrongUsernameOrPasswordError') return { kind: 'wrong_credentials', code: err.identifier == null ? '' : String(err.identifier), message: String(err.message ?? '') };
  if (name === 'ValidationError') return { kind: 'validation', code: String(err.code ?? ''), message: String(err.message ?? '') };
  if (name === 'UnauthorizedError') return { kind: 'unauthorized', code: '', message: String(err.message ?? '') };
  return { kind: 'error', code: '', message: String((err && err.message) ?? err ?? 'error').slice(0, 1024) };
}

function respond(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

function run(req) {
  let done = false;
  const finish = (err, value) => {
    if (done) { log(req.conn, 'warn', [`${req.name}: callback called more than once; ignored`]); return; }
    done = true;
    if (err) { respond({ id: req.id, ok: false, error: toWireError(err) }); return; }
    let line;
    try {
      line = JSON.stringify({ id: req.id, ok: true, result: value === undefined ? null : value });
    } catch (e) {
      respond({ id: req.id, ok: false, error: toWireError(new Error(`${req.name}: the callback value is not JSON: ${e && e.message}`)) });
      return;
    }
    process.stdout.write(line + '\n');
  };
  try {
    const fn = compile(req);
    const out = fn(...(Array.isArray(req.args) ? req.args : []), finish);
    if (out && typeof out.then === 'function') out.then(undefined, (e) => finish(e));
  } catch (e) { finish(e); }
}

function log(conn, level, args) {
  const msg = args.map((a) => (typeof a === 'string' ? a : safeJSON(a))).join(' ').slice(0, 2048);
  process.stderr.write(JSON.stringify({ conn, level, msg }) + '\n');
}
function safeJSON(v) { try { const s = JSON.stringify(v); return s === undefined ? String(v) : s; } catch { return String(v); } }

process.on('uncaughtException', (e) => log('', 'error', ['uncaught: ' + (e && e.message)]));
process.on('unhandledRejection', (e) => log('', 'error', ['unhandled rejection: ' + (e && e.message)]));
readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  run(req);
}).on('close', () => process.exit(0));
