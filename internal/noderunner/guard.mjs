// zeroauthy runner guard, shared by the Actions and custom database runners.
// Each runner imports it first, before any tenant code exists.
//
// Node's permission model does not cover connect() to a unix-domain socket
// path (Node 22/24 have no network permission; --allow-net on 25+ allows
// pipes too), so tenant code running as the server's uid could reach
// peer-auth databases or container-runtime sockets. TCP stays open (spec §2).
//
// net, tls, http(s) (socketPath, Agent), http2 and undici all connect through
// net.Socket.prototype.connect. The wrapper reads the caller's arguments once
// into fresh data, checks that snapshot and passes only the snapshot on, so an
// accessor or Proxy cannot answer the check differently from Node's own read.
// The native Pipe handle's connect is locked too: tenant code can reach the
// Pipe class through process.stdin._handle and call it directly.
//
// This is in-process hardening, not a sandbox boundary (D-0053).
import net from 'node:net';

const message = 'unix-domain sockets are not available to tenant code';
const refuse = () => { throw new Error(message); };

// Node's isPipeName: a string that is not a non-negative number.
const isPipeName = (s) => typeof s === 'string' && !(Number(s) >= 0);

// copyOptions reads each enumerable property (own or inherited) once, then
// path exactly once, into a null-prototype object Node reads from instead.
function copyOptions(src) {
  const out = { __proto__: null };
  for (const key in src) {
    if (key !== 'path') out[key] = src[key];
  }
  out.path = src.path;
  return out;
}

// snapshot mirrors Node's normalizeArgs on a copy: [options, cb].
function snapshot(args) {
  let a = args; // rest parameters: already a fresh array
  // Node's own callers pass one internally normalized [options, cb] array.
  if (a.length > 0 && Array.isArray(a[0])) { const inner = a[0]; a = [inner[0], inner[1]]; }
  const last = a.length > 0 ? a[a.length - 1] : undefined;
  const cb = typeof last === 'function' ? last : null;
  const a0 = a[0];
  let options;
  if (a0 !== null && typeof a0 === 'object') {
    options = copyOptions(a0);
  } else if (isPipeName(a0)) {
    refuse();
  } else {
    options = { __proto__: null, path: undefined, port: a0 };
    if (a.length > 1 && typeof a[1] === 'string') options.host = a[1];
  }
  if (options.path != null) refuse();
  return [options, cb];
}

const connect = net.Socket.prototype.connect;
Object.defineProperty(net.Socket.prototype, 'connect', {
  value: function connect_(...args) {
    const [options, cb] = snapshot(args);
    return cb ? connect.call(this, options, cb) : connect.call(this, options);
  },
  writable: false, enumerable: false, configurable: false,
});

// The runners talk over stdio pipes, so one of these handles is a Pipe. Fail
// closed if none is: without the class its connect cannot be locked.
let Pipe;
for (const stream of [process.stdin, process.stdout, process.stderr]) {
  const handle = stream && stream._handle;
  if (handle && handle.constructor && handle.constructor.name === 'Pipe') { Pipe = handle.constructor; break; }
}
if (!Pipe) throw new Error('zeroauthy runner guard: stdio is not a pipe; refusing to start');
Object.defineProperty(Pipe.prototype, 'connect', {
  value: refuse, writable: false, enumerable: false, configurable: false,
});
