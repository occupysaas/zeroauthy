// Package guardtest holds the unix-socket attack list that both Node runners
// (Actions and custom databases) must refuse. Tests in each runner's package
// run Probe inside a real runner process and pass the result to Check, so the
// two runners are held to the same list.
package guardtest

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Target is a unix-socket listener that counts accepted connections and a TCP
// listener that answers "tcp", which must stay reachable.
type Target struct {
	Sock     string
	Port     int
	accepted atomic.Int32
}

// Listen starts both listeners for the test.
func Listen(t *testing.T) *Target {
	t.Helper()
	dir, err := os.MkdirTemp("", "za-sock") // short path: sun_path is ~108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	tg := &Target{Sock: filepath.Join(dir, "s")}
	unix, err := net.Listen("unix", tg.Sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close() })
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	tg.Port = tcp.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := unix.Accept()
			if err != nil {
				return
			}
			tg.accepted.Add(1)
			_ = c.Close()
		}
	}()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("tcp"))
			_ = c.Close()
		}
	}()
	return tg
}

// Probe is a JavaScript expression that evaluates to a Promise of an object
// mapping each attack to "denied" (refused by the guard), "allowed" or an
// error code. It needs require (any Node built-in) and the real process.
func (tg *Target) Probe() string {
	return fmt.Sprintf(`(async () => {
  const net = require("net"), tls = require("tls"), http = require("http"), https = require("https");
  const sock = %q, abstract = "\0za-guard-" + process.pid, port = %d, out = {};
  const quiet = (s) => { try { if (s && typeof s.on === "function") s.on("error", () => {}); } catch {} return s; };
  const try_ = (name, f) => {
    try { quiet(f()); out[name] = "allowed"; }
    catch (e) { out[name] = /unix-domain sockets/.test(String(e && e.message)) ? "denied" : "error:" + ((e && e.code) || (e && e.message)); }
  };
  // Accessors that change their answer between reads (time of check vs use).
  // Only the outcome on the unix listener matters for these.
  const flip = (k, hit) => { let n = 0; return { get path() { n++; return (n === k) === hit ? sock : undefined; } }; };
  for (let k = 1; k <= 4; k++) {
    for (const hit of [true, false]) {
      const attempt = (f) => { try { quiet(f()); } catch {} };
      attempt(() => net.connect(flip(k, hit)));
      attempt(() => net.createConnection(flip(k, hit)));
      attempt(() => new net.Socket().connect(flip(k, hit)));
      attempt(() => tls.connect(flip(k, hit)));
      let n = 0;
      attempt(() => http.get({ get socketPath() { n++; return (n === k) === hit ? sock : undefined; }, path: "/" }));
      attempt(() => net.connect(new Proxy({}, { get: (_, p) => (p === "path" ? ((n++ === k) === hit ? sock : undefined) : undefined) })));
    }
  }
  try_("string", () => net.connect(sock));
  try_("string_cb", () => net.connect(sock, () => {}));
  try_("abstract", () => net.connect(abstract));
  try_("options", () => net.createConnection({ path: sock }));
  try_("inherited", () => net.connect(Object.create({ path: sock })));
  try_("hidden", () => net.connect(Object.defineProperty({}, "path", { value: sock, enumerable: false })));
  try_("socket", () => new net.Socket().connect(sock));
  try_("socket_options", () => new net.Socket().connect({ path: sock }));
  try_("tls", () => tls.connect({ path: sock }));
  try_("tls_string", () => tls.connect(sock));
  try_("http", () => http.get({ socketPath: sock, path: "/" }));
  try_("http_request", () => http.request({ socketPath: sock, path: "/" }).end());
  try_("https", () => https.get({ socketPath: sock, path: "/" }));
  try_("agent", () => http.get({ agent: new http.Agent({ socketPath: sock }), path: "/" }));
  // A raw Pipe handle (reachable from process.stdin) with a connect request
  // object captured from Node's own TCP connect.
  out.pipe_handle = await new Promise((resolve) => {
    // Node's objects inherit the main realm's Object.prototype, not the vm's.
    const OP = Object.getPrototypeOf(require("events").EventEmitter.prototype);
    let req;
    Object.defineProperty(OP, "oncomplete", { configurable: true, set(v) {
      req ??= this; Object.defineProperty(this, "oncomplete", { value: v, writable: true, configurable: true });
    } });
    const c = net.connect(port, "127.0.0.1", () => {
      delete OP.oncomplete;
      c.destroy();
      try {
        const Pipe = process.stdin._handle.constructor, Wrap = req.constructor;
        const p = new Pipe(1), r = new Wrap();
        r.oncomplete = () => {};
        p.connect(r, sock);
        resolve("allowed");
      } catch (e) { resolve(/unix-domain sockets/.test(String(e && e.message)) ? "denied" : "error:" + e.message); }
    });
    c.on("error", (e) => { delete OP.oncomplete; resolve("tcp-error:" + e.code); });
  });
  out.tcp = await new Promise((resolve) => {
    const c = net.connect(port, "127.0.0.1");
    c.on("data", (d) => resolve(String(d)));
    c.on("error", (e) => resolve(e.code));
  });
  out.tcp_options = await new Promise((resolve) => {
    const c = net.connect({ port, host: "127.0.0.1" });
    c.on("data", (d) => resolve(String(d)));
    c.on("error", (e) => resolve(e.code));
  });
  out.tcp_string_port = await new Promise((resolve) => {
    const c = net.connect(String(port), "127.0.0.1");
    c.on("data", (d) => resolve(String(d)));
    c.on("error", (e) => resolve(e.code));
  });
  return out;
})()`, tg.Sock, tg.Port)
}

// Want is the result every runner must produce.
var Want = map[string]string{
	"string": "denied", "string_cb": "denied", "abstract": "denied", "options": "denied",
	"inherited": "denied", "hidden": "denied", "socket": "denied", "socket_options": "denied",
	"tls": "denied", "tls_string": "denied", "http": "denied", "http_request": "denied",
	"https": "denied", "agent": "denied", "pipe_handle": "denied",
	"tcp": "tcp", "tcp_options": "tcp", "tcp_string_port": "tcp",
}

// Check compares the probe result with Want and asserts that the unix
// listener never accepted a connection.
func (tg *Target) Check(t *testing.T, got []byte) {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("probe result %s: %v", got, err)
	}
	for k, w := range Want {
		if m[k] != w {
			t.Errorf("%s = %q, want %q", k, m[k], w)
		}
	}
	for k := range m {
		if _, ok := Want[k]; !ok {
			t.Errorf("unexpected probe key %s", k)
		}
	}
	time.Sleep(300 * time.Millisecond)
	if n := tg.accepted.Load(); n != 0 {
		t.Errorf("unix socket accepted %d connections", n)
	}
}
