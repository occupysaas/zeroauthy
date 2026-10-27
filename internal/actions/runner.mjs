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
import { createHash } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import { AsyncLocalStorage } from 'node:async_hooks';

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

// buildApi returns the api object for one call. Mutating methods record a
// command and return api (Auth0's api methods chain); readers answer from
// the request. Namespaces zeroauthy does not support throw, so a copied
// Action never silently skips a security check.
function buildApi(req, commands) {
  const api = {};
  const recorder = (ns) => new Proxy({}, {
    get(_, method) {
      // Not methods: symbols, 'then' (so api parts are not thenables) and
      // Object.prototype members.
      if (typeof method !== 'string' || method === 'then' || method in Object.prototype) return undefined;
      return (...args) => {
        const op = ns + '.' + method;
        commands.push({ op, args: json(op, args) });
        return api;
      };
    },
  });
  const unsupported = (ns) => new Proxy({}, {
    get(_, method) {
      if (typeof method !== 'string' || method === 'then' || method in Object.prototype) return undefined;
      return () => { throw new Error(`api.${ns}.${method} is not supported by zeroauthy`); };
    },
  });
  const cache = new Map(Object.entries(req.cache ?? {}));
  const cacheApi = {
    get(key) { const r = cache.get(String(key)); return r === undefined ? undefined : json('cache.get', r); },
    set(key, value, options) {
      const record = { value: String(value) };
      if (options && options.expires_at !== undefined) record.expires_at = options.expires_at;
      commands.push({ op: 'cache.set', args: json('cache.set', [String(key), String(value), options ?? null]) });
      cache.set(String(key), record);
      return { type: 'success', record: { ...record } };
    },
    delete(key) {
      commands.push({ op: 'cache.delete', args: [String(key)] });
      cache.delete(String(key));
      return { type: 'success' };
    },
  };
  const roles = Array.isArray(req.roles) ? req.roles : [];
  const state = req.state ?? {};
  api.access = recorder('access');
  api.accessToken = recorder('accessToken');
  api.transaction = recorder('transaction');
  api.cache = cacheApi;
  if (req.handler !== 'onExecuteCredentialsExchange') {
    api.idToken = recorder('idToken');
    api.user = recorder('user');
    api.redirect = new Proxy({}, {
      get(_, method) {
        if (method === 'canRedirect') return () => state.canRedirect === true;
        if (method === 'sendUserTo') return (...args) => { commands.push({ op: 'redirect.sendUserTo', args: json('redirect.sendUserTo', args) }); return api; };
        if (typeof method !== 'string') return undefined;
        return () => { throw new Error(`api.redirect.${method} is not supported by zeroauthy`); };
      },
    });
    api.roles = {
      getUserEffectiveRoles: async () => json('roles', roles),
      getUserEffectiveRolesByIds: async (ids) => json('roles', roles.filter((r) => (ids ?? []).includes(r && r.id))),
      getUserEffectiveRolesByNames: async (names) => json('roles', roles.filter((r) => (names ?? []).includes(r && r.name))),
    };
    api.groups = { getUserGroups: async () => [], hasGroupMembership: async () => false };
    api.rules = { wasExecuted: () => false };
    for (const ns of unsupportedNamespaces) api[ns] = unsupported(ns);
  }
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
      await fn(event, buildApi(req, commands));
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
