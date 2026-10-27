// zeroauthy social profile script runner. One process runs one
// fetchUserProfile execution and exits.
//
// The host starts it with an empty environment and Node's permission model
// without --allow-net (Node 25+ denies sockets and fetch), read access only to
// this file, and a small heap. The vm context is a convenience, not the
// security boundary: the process is. The only way out is the host broker,
// reached through request.get / request({method:'GET'}).
//
// Protocol, JSON lines: the host writes {exec, source, accessToken, context};
// the runner writes {exec, type:"get", id, options} and the host answers
// {exec, type:"get_result", id, error?, response?, body?}; the runner ends
// with {exec, type:"done", error?, profile?}. Console output is discarded.
import vm from 'node:vm';
import readline from 'node:readline';
import os from 'node:os';

function lockOut(obj, name) {
  Object.defineProperty(obj, name, {
    value: () => { throw new Error('not available to profile scripts'); },
    writable: false, enumerable: false, configurable: false,
  });
}
lockOut(process, 'kill');
lockOut(process, '_kill');
lockOut(process, '_debugProcess');
lockOut(process, '_debugEnd');
lockOut(os, 'setPriority');

const out = (m) => process.stdout.write(JSON.stringify(m) + '\n');
let execID = '';
let finished = false;
const pending = new Map();
let nextID = 1;

function finish(error, profile) {
  if (finished) return;
  finished = true;
  const m = { exec: execID, type: 'done' };
  if (error) m.error = String(error);
  else m.profile = profile;
  process.stdout.write(JSON.stringify(m) + '\n', () => process.exit(0));
}

function brokerGet(options, callback) {
  if (typeof callback !== 'function') throw new TypeError('request needs a callback');
  if (typeof options === 'string') options = { url: options };
  if (options === null || typeof options !== 'object') throw new TypeError('request options must be an object');
  const method = String(options.method || 'GET').toUpperCase();
  if (method !== 'GET') throw new Error('only GET requests are supported');
  const url = options.url ?? options.uri;
  if (typeof url !== 'string') throw new TypeError('request options.url must be a string');
  const headers = {};
  for (const [k, v] of Object.entries(options.headers || {})) headers[String(k)] = String(v);
  const id = nextID++;
  pending.set(id, { callback, json: options.json === true });
  process.stdin.ref(); // wait for the host's answer
  out({ exec: execID, type: 'get', id, options: { url, headers, json: options.json === true } });
}

function request(options, callback) { return brokerGet(options, callback); }
request.get = brokerGet;

function onResult(m) {
  const p = pending.get(m.id);
  if (!p) return;
  pending.delete(m.id);
  if (pending.size === 0) process.stdin.unref();
  if (m.error) {
    p.callback(new Error(m.error));
    return;
  }
  let body = m.body;
  if (p.json) {
    try { body = JSON.parse(body); } catch { p.callback(new Error('response body is not JSON')); return; }
  }
  p.callback(null, { statusCode: m.response.statusCode, headers: m.response.headers }, body);
}

function run(m) {
  execID = String(m.exec);
  const silent = () => {};
  const sandbox = {
    request,
    console: { log: silent, info: silent, warn: silent, error: silent, debug: silent },
    setTimeout, clearTimeout,
  };
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  let fn;
  try {
    fn = new vm.Script(`${m.source}\n;typeof fetchUserProfile === 'function' ? fetchUserProfile : undefined`, { filename: 'fetchUserProfile.js' })
      .runInContext(context, { timeout: 1000 });
  } catch (e) {
    finish('script failed to compile: ' + (e && e.name));
    return;
  }
  if (typeof fn !== 'function') {
    finish('fetchUserProfile is not defined');
    return;
  }
  let calls = 0;
  const callback = (err, profile) => {
    calls++;
    if (calls > 1) {
      finish('callback called more than once');
      return;
    }
    // Finish on the next turn so a second synchronous call is caught.
    setImmediate(() => {
      if (calls > 1) return;
      if (err) finish('script returned an error');
      else finish(null, profile === undefined ? null : profile);
    });
  };
  try {
    fn(m.accessToken, m.context || {}, callback);
  } catch (e) {
    finish('script threw: ' + (e && e.name));
  }
}

const rl = readline.createInterface({ input: process.stdin });
let started = false;
rl.on('line', (line) => {
  let m;
  try { m = JSON.parse(line); } catch { process.exit(3); }
  if (!started) {
    started = true;
    // Only pending broker requests keep the process alive through stdin; a
    // script that stops without calling back lets the loop drain and exit.
    process.stdin.unref();
    run(m);
    return;
  }
  if (m.exec !== execID || m.type !== 'get_result') process.exit(3);
  onResult(m);
});
rl.on('close', () => { if (!finished) process.exit(4); });
process.on('beforeExit', () => { if (!finished) process.exit(4); });
