// zeroauthy Actions runner. One process serves one tenant's Actions; custom
// databases run in separate processes.
//
// Protocol: one JSON request per stdin line,
//   {id, version_key, code, deps_root, handler, event, secrets, cache, roles, state, hostname}
// one JSON response per stdout line,
//   {id, commands: [{op, args}], logs: [string], error?: {message, stack}}
// The handler records api calls as commands; the server validates and
// applies them, so nothing here is trusted as token contents.
//
// The host starts this file with an empty environment and Node's permission
// model (--permission, read access only to this directory and the tenant's
// build root). The vm contexts below are a convenience, not a security
// boundary: the process boundary is.
import vm from 'node:vm';
import readline from 'node:readline';
import { createRequire, builtinModules } from 'node:module';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { AsyncLocalStorage } from 'node:async_hooks';
import net from 'node:net';

// Node's permission model does not stop signals to other processes of the
// same uid (zeroauthy itself, other tenants' runners). Lock those APIs before
// any Action runs; module objects are shared, so this also covers code that
// escapes the vm context (D-0022 addendum).
function lockOut(obj, name, what) {
  Object.defineProperty(obj, name, {
    value: () => { throw new Error(`${what} is not available to Actions`); },
    writable: false, enumerable: false, configurable: false,
  });
}
lockOut(process, 'kill', 'process.kill');
lockOut(process, '_kill', 'process.kill');
lockOut(process, '_debugProcess', 'process._debugProcess');
lockOut(process, '_debugEnd', 'process._debugEnd');
lockOut(os, 'setPriority', 'os.setPriority');

// Node's permission model does not cover connect() to a unix-domain socket
// path (Node 22/24 have no network permission; --allow-net on 25+ allows
// pipes too), so code running as the server's uid could reach peer-auth
// databases or container-runtime sockets. net, tls and http (socketPath) all
// connect through Socket.prototype.connect; refuse path-based connections
// there. TCP stays open (spec §2).
function socketPath(args) {
  let a = args[0];
  if (Array.isArray(a)) a = a[0]; // internally normalized [options, cb]
  if (a !== null && typeof a === 'object') return a.path != null;
  return typeof a === 'string' && !/^\s*\d+\s*$/.test(a);
}
const connect = net.Socket.prototype.connect;
Object.defineProperty(net.Socket.prototype, 'connect', {
  value: function (...args) {
    if (socketPath(args)) throw new Error('unix-domain sockets are not available to Actions');
    return connect.apply(this, args);
  },
  writable: false, enumerable: false, configurable: false,
});

const handlers = new Set(['onExecutePostLogin', 'onContinuePostLogin', 'onExecuteCredentialsExchange']);

// The denylist only gives clear errors; --permission is the control.
const denied = new Set(['child_process', 'cluster', 'worker_threads', 'inspector', 'vm', 'v8', 'module', 'repl', 'wasi', 'trace_events']);
const builtinRequire = createRequire(import.meta.url);

// requireFor confines require to Node built-ins and the packages installed
// in depsRoot/node_modules for one version.
function requireFor(depsRoot) {
  const modules = depsRoot ? path.join(path.resolve(depsRoot), 'node_modules') : '';
  const resolver = modules ? createRequire(path.join(modules, 'noop.js')) : null;
  return function require(name) {
    const spec = String(name);
    const bare = spec.replace(/^node:/, '');
    if (denied.has(bare)) throw new Error(`module "${bare}" is not available to Actions`);
    if (spec.startsWith('node:') || builtinModules.includes(bare)) return builtinRequire('node:' + bare);
    const missing = () => new Error(`module "${spec}" is not a dependency of this Action`);
    if (!resolver || spec.startsWith('.') || path.isAbsolute(spec)) throw missing();
    let file;
    try { file = resolver.resolve(spec); } catch { throw missing(); }
    if (!file.startsWith(modules + path.sep)) throw missing();
    return resolver(file);
  };
}

// Console output of the current request, returned in its response.
const captured = new AsyncLocalStorage();
const maxLogs = 100;
const maxLogChars = 2048;

function str(v) { try { return String(v); } catch { return '[unprintable]'; } }
function safeJSON(v) { try { const s = JSON.stringify(v); return s === undefined ? str(v) : s; } catch { return str(v); } }
function log(level, args) {
  const sink = captured.getStore();
  if (!sink || sink.length >= maxLogs) return;
  const msg = args.map((a) => (typeof a === 'string' ? a : safeJSON(a))).join(' ').slice(0, maxLogChars);
  sink.push(level === 'info' ? msg : level + ': ' + msg);
}
const logger = (level) => (...a) => log(level, a);
const console_ = { log: logger('info'), info: logger('info'), warn: logger('warn'), error: logger('error'), debug: logger('debug') };

// One vm context per deployed version; least recently used evicted.
const versions = new Map(); // version_key → {hash, ctx, exports}
const maxVersions = 256;

function load(req) {
  const key = String(req.version_key ?? '');
  if (!key) throw new Error('version_key is required');
  const hash = createHash('sha256').update(String(req.code ?? '')).update('\0').update(String(req.deps_root ?? '')).digest('hex');
  let v = versions.get(key);
  if (v && v.hash === hash) {
    versions.delete(key);
    versions.set(key, v);
    return v;
  }
  const ctx = vm.createContext({
    console: console_,
    setTimeout, clearTimeout, setInterval, clearInterval, setImmediate, clearImmediate, queueMicrotask,
    Buffer, URL, URLSearchParams, TextEncoder, TextDecoder, AbortController, AbortSignal,
    fetch, Headers, Request, Response, FormData, Blob, crypto: globalThis.crypto,
    atob, btoa, structuredClone,
    // The real process: its env is empty and --permission guards the rest.
    process,
  }, { name: 'action:' + key });
  const module = { exports: {} };
  const filename = `action-${key}.js`;
  const wrapper = new vm.Script('(function (exports, require, module, __filename, __dirname) {\n' + String(req.code ?? '') + '\n})', { filename, lineOffset: -1 })
    .runInContext(ctx);
  wrapper.call(module.exports, module.exports, requireFor(req.deps_root), module, filename, '/');
  v = { hash, ctx, exports: module.exports, parse: vm.runInContext('JSON.parse', ctx) };
  versions.delete(key);
  versions.set(key, v);
  while (versions.size > maxVersions) versions.delete(versions.keys().next().value);
  return v;
}

// json copies v as JSON (the server's side of a command), or throws.
function json(op, v) {
  let s;
  try { s = JSON.stringify(v, (k, x) => (x === undefined ? null : x)); } catch { s = undefined; }
  if (s === undefined) throw new TypeError(`api.${op}: arguments must be JSON values`);
  return JSON.parse(s);
}

const unsupportedNamespaces = ['session', 'refreshToken', 'authentication', 'multifactor', 'prompt', 'samlResponse'];

const utf8Bytes = (s) => Buffer.byteLength(s, 'utf8');
const cacheKeyMax = 64;
const cacheValueMax = 4096;
const cacheDefaultTTL = 15 * 60 * 1000;
const cacheMaxTTL = 24 * 60 * 60 * 1000;
const rolesTakeMax = 100;
const rolesIdsMax = 100;
const rolesNamesMax = 50;
const rolesTakeDefault = 50;

// clone copies a JSON value into the Action's realm.
const cloneInto = (parse, v) => parse(JSON.stringify(v));

// buildApi returns the api object for one call. Mutating methods record a
// command and return api (Auth0's api methods chain); readers answer from
// the request. The server validates every command again and refuses unknown
// ones, so nothing here is trusted. Unsupported members record an
// "unsupported" command before they throw: an Action that catches the error
// still fails its flow, so a copied Action never silently skips a security
// check.
function buildApi(req, commands, event, parse) {
  const api = {};
  const record = (op, args) => { commands.push({ op, args: json(op, args) }); return api; };
  const method = (ns, name) => (...args) => record(ns + '.' + name, args);
  const ns = (name, methods) => Object.fromEntries(methods.map((m) => [m, method(name, m)]));
  const unsupported = (name) => new Proxy({}, {
    get(_, m) {
      if (typeof m !== 'string' || m === 'then' || m in Object.prototype) return undefined;
      return () => {
        commands.push({ op: 'unsupported', args: [`${name}.${m}`] });
        throw new Error(`api.${name}.${m} is not supported by zeroauthy`);
      };
    },
  });
  const postLogin = req.handler !== 'onExecuteCredentialsExchange';

  // Target scopes and transaction metadata are visible at once in event
  // (Auth0 documents both as real time).
  const txn = event && typeof event.transaction === 'object' && event.transaction ? event.transaction : null;
  const targets = () => {
    if (!txn) return null;
    if (!Array.isArray(txn.target_scopes)) txn.target_scopes = parse('[]');
    return txn.target_scopes;
  };
  const scopeArg = (op, s) => { if (typeof s !== 'string' || s === '') throw new TypeError(`api.${op}: scope must be a non-empty string`); return s; };
  api.transaction = {
    addTargetScope(scope) {
      scopeArg('transaction.addTargetScope', scope);
      const t = targets(); if (t && !t.includes(scope)) t.push(scope);
      return record('transaction.addTargetScope', [scope]);
    },
    removeTargetScope(scope) {
      scopeArg('transaction.removeTargetScope', scope);
      const t = targets(); if (t) { const i = t.indexOf(scope); if (i >= 0) t.splice(i, 1); }
      return record('transaction.removeTargetScope', [scope]);
    },
    setTargetScopes(scopes) {
      if (!Array.isArray(scopes)) throw new TypeError('api.transaction.setTargetScopes: scopes must be an array of strings');
      scopes.forEach((s) => scopeArg('transaction.setTargetScopes', s));
      const t = targets(); if (t) { t.length = 0; for (const s of scopes) if (!t.includes(s)) t.push(s); }
      return record('transaction.setTargetScopes', [scopes]);
    },
    clearTargetScopes() {
      const t = targets(); if (t) t.length = 0;
      return record('transaction.clearTargetScopes', []);
    },
  };
  api.access = postLogin ? ns('access', ['deny']) : { deny: (code, reason) => record('access.deny', reason === undefined ? [code] : [code, reason]) };
  api.accessToken = postLogin ? ns('accessToken', ['setCustomClaim', 'addScope', 'removeScope']) : ns('accessToken', ['setCustomClaim']);

  const cache = new Map(Object.entries(req.cache ?? {}));
  api.cache = {
    get(key) { const r = cache.get(String(key)); return r === undefined ? undefined : cloneInto(parse, r); },
    set(key, value, options) {
      const k = String(key), v = String(value);
      if (k === '' || utf8Bytes(k) > cacheKeyMax) throw new RangeError(`api.cache.set: key must be 1-${cacheKeyMax} bytes`);
      if (utf8Bytes(v) > cacheValueMax) throw new RangeError(`api.cache.set: value exceeds ${cacheValueMax} bytes`);
      const opts = {};
      if (options != null) {
        if (typeof options !== 'object') throw new TypeError('api.cache.set: options must be an object');
        for (const f of ['ttl', 'expires_at']) {
          if (options[f] === undefined) continue;
          if (typeof options[f] !== 'number' || !Number.isFinite(options[f]) || options[f] <= 0) throw new TypeError(`api.cache.set: ${f} must be a positive number`);
          opts[f] = Math.floor(options[f]);
        }
      }
      const now = Date.now();
      let exp = now + Math.min(opts.ttl ?? cacheDefaultTTL, cacheMaxTTL);
      if (opts.expires_at !== undefined) exp = Math.min(exp, opts.expires_at);
      exp = Math.min(exp, now + cacheMaxTTL);
      commands.push({ op: 'cache.set', args: [k, v, opts] });
      const r = { value: v, expires_at: exp };
      cache.set(k, r);
      return cloneInto(parse, { type: 'success', record: r });
    },
    delete(key) {
      const k = String(key);
      commands.push({ op: 'cache.delete', args: [k] });
      cache.delete(k);
      return cloneInto(parse, { type: 'success' });
    },
  };
  if (!postLogin) return api;

  api.idToken = ns('idToken', ['setCustomClaim']);
  api.user = ns('user', ['setAppMetadata', 'setUserMetadata']);
  api.validation = ns('validation', ['error']);
  api.transaction.setMetadata = (key, value) => {
    record('transaction.setMetadata', [key, value]);
    if (txn && typeof key === 'string') {
      if (!txn.metadata || typeof txn.metadata !== 'object') txn.metadata = parse('{}');
      if (value === null || value === undefined) delete txn.metadata[key];
      else txn.metadata[key] = cloneInto(parse, value);
    }
    return api;
  };
  const state = req.state ?? {};
  api.redirect = {
    canRedirect: () => state.canRedirect === true,
    sendUserTo: (...args) => record('redirect.sendUserTo', args),
    encodeToken(options) {
      const { payload = {}, secret, expiresInSeconds = 900 } = options ?? {};
      if (typeof secret !== 'string' || !secret || !payload || typeof payload !== 'object' || Array.isArray(payload) || !Number.isFinite(expiresInSeconds) || expiresInSeconds <= 0) throw new TypeError('api.redirect.encodeToken: invalid options');
      const now = Math.floor(Date.now() / 1000);
      const claims = { ...json('redirect.encodeToken', payload), sub: event.user?.user_id, iss: req.hostname, iat: now, exp: now + expiresInSeconds, ip: event.request?.ip };
      const part = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
      const data = part({ alg: 'HS256', typ: 'JWT' }) + '.' + part(claims);
      return data + '.' + createHmac('sha256', secret).update(data).digest('base64url');
    },
    validateToken(options) {
      const { secret, tokenParameterName = 'session_token' } = options ?? {};
      if (typeof secret !== 'string' || !secret || typeof tokenParameterName !== 'string' || !tokenParameterName) throw new TypeError('api.redirect.validateToken: invalid options');
      const token = event.request?.query?.[tokenParameterName] ?? event.request?.body?.[tokenParameterName];
      try {
        if (typeof token !== 'string' || token.length > 128 * 1024) throw new Error();
        const parts = token.split('.');
        if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) throw new Error();
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
        if (header.alg !== 'HS256') throw new Error();
        const signature = Buffer.from(parts[2], 'base64url');
        const expected = createHmac('sha256', secret).update(parts[0] + '.' + parts[1]).digest();
        if (signature.length !== expected.length || !timingSafeEqual(signature, expected)) throw new Error();
        const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
        if (!claims || typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000 || typeof state.state !== 'string' || !state.state || claims.state !== state.state) throw new Error();
        return cloneInto(parse, claims);
      } catch { throw new Error('api.redirect.validateToken: invalid token'); }
    },
  };

  // Roles come from the snapshot taken when the flow started.
  const roles = Array.isArray(req.roles) ? req.roles : [];
  const out = (v) => Promise.resolve(cloneInto(parse, v));
  const stringList = (op, v, max) => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== 'string')) throw new TypeError(`api.roles.${op}: expects an array of strings`);
    if (v.length > max) throw new RangeError(`api.roles.${op}: at most ${max} values`);
    return v;
  };
  api.roles = {
    getUserEffectiveRoles(params) {
      const p = params ?? {};
      const take = p.take === undefined ? rolesTakeDefault : p.take;
      if (!Number.isInteger(take) || take < 1 || take > rolesTakeMax) return Promise.reject(new RangeError(`api.roles.getUserEffectiveRoles: take must be 1-${rolesTakeMax}`));
      let from = 0;
      if (p.from !== undefined && p.from !== null && p.from !== '') {
        const n = /^[0-9]{1,9}$/.test(String(p.from)) ? Number(p.from) : NaN;
        if (!Number.isInteger(n) || n > roles.length) return Promise.reject(new TypeError('api.roles.getUserEffectiveRoles: invalid from'));
        from = n;
      }
      const page = roles.slice(from, from + take);
      const res = { roles: page };
      if (from + take < roles.length) res.next = String(from + take);
      return out(res);
    },
    getUserEffectiveRolesByIds(ids) {
      try { stringList('getUserEffectiveRolesByIds', ids, rolesIdsMax); } catch (e) { return Promise.reject(e); }
      return out({ roles: roles.filter((r) => ids.includes(r && r.id)) });
    },
    getUserEffectiveRolesByNames(names) {
      try { stringList('getUserEffectiveRolesByNames', names, rolesNamesMax); } catch (e) { return Promise.reject(e); }
      return out({ roles: roles.filter((r) => names.includes(r && r.name)) });
    },
  };
  api.groups = { getUserGroups: () => out({ groups: [] }), hasGroupMembership: () => Promise.resolve(false) };
  api.rules = { wasExecuted: () => false };
  for (const name of unsupportedNamespaces) api[name] = unsupported(name);
  return api;
}

function respond(obj) { process.stdout.write(JSON.stringify(obj) + '\n'); }

function errorOf(e) {
  let message, stack;
  try { message = str(e && e.message !== undefined ? e.message : e); } catch { message = '[unprintable]'; }
  try { stack = str((e && e.stack) ?? ''); } catch { stack = ''; }
  return { message: message.slice(0, 1024), stack: stack.slice(0, 4096) };
}

async function run(req) {
  const commands = [];
  const logs = [];
  let error;
  await captured.run(logs, async () => {
    try {
      if (!handlers.has(req.handler)) throw new Error(`unknown handler "${str(req.handler)}"`);
      const v = load(req);
      const fn = v.exports && v.exports[req.handler];
      if (typeof fn !== 'function') throw new Error(`the Action does not export ${req.handler}`);
      // Build event in the Action's own realm.
      const event = v.parse(JSON.stringify(req.event ?? {}));
      event.secrets = v.parse(JSON.stringify(req.secrets ?? {}));
      await fn(event, buildApi(req, commands, event, v.parse));
    } catch (e) {
      error = errorOf(e);
    }
  });
  let line;
  try {
    line = JSON.stringify(error ? { id: req.id, commands, logs, error } : { id: req.id, commands, logs });
  } catch {
    line = JSON.stringify({ id: req.id, commands: [], logs: [], error: { message: 'the Action produced an unencodable response', stack: '' } });
  }
  process.stdout.write(line + '\n');
}

function errText(e) { try { return str(e && e.message); } catch { return '[unprintable]'; } }
process.on('uncaughtException', (e) => process.stderr.write(JSON.stringify({ level: 'error', msg: 'uncaught: ' + errText(e).slice(0, 1024) }) + '\n'));
process.on('unhandledRejection', (e) => process.stderr.write(JSON.stringify({ level: 'error', msg: 'unhandled rejection: ' + errText(e).slice(0, 1024) }) + '\n'));
readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let req;
  try { req = JSON.parse(line); } catch { return; }
  run(req).catch((e) => respond({ id: req.id, commands: [], logs: [], error: errorOf(e) }));
}).on('close', () => process.exit(0));
