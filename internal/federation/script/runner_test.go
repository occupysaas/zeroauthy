package script

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// newTestRunner requires a capable Node: this is the dedicated acceptance
// lane for the runner, so a missing runtime fails rather than skips.
func newTestRunner(t *testing.T, client *http.Client) *Runner {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatalf("node is required for the profile script lane: %v", err)
	}
	r, err := NewRunner(Config{}, NewBroker(client))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Probe(); err != nil {
		t.Fatalf("runner capability probe: %v", err)
	}
	return r
}

func run(t *testing.T, r *Runner, src string) (map[string]any, error) {
	t.Helper()
	raw, err := r.Execute(context.Background(), Request{TenantID: "ten", ConnectionID: "con", Source: src,
		AccessToken: "upstream-access-token", Context: map[string]any{"token_type": "Bearer", "scope": "read"}})
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("result %s", raw)
	}
	return m, nil
}

func TestProfileScript(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer upstream-access-token" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":42,"login":"octo","mail":"o@example.com"}`))
	}))
	defer api.Close()
	r := newTestRunner(t, tlsClient(api))

	t.Run("callback", func(t *testing.T) {
		m, err := run(t, r, `function fetchUserProfile(accessToken, context, callback) {
			callback(null, {user_id: 'u-' + context.scope, email: 'a@example.com', has_token: accessToken.length > 0});
		}`)
		if err != nil || m["user_id"] != "u-read" || m["has_token"] != true {
			t.Fatalf("%v %v", m, err)
		}
	})
	t.Run("request.get", func(t *testing.T) {
		m, err := run(t, r, `function fetchUserProfile(accessToken, context, callback) {
			request.get({url: '`+api.URL+`/me', headers: {Authorization: 'Bearer ' + accessToken}, json: true}, function (e, resp, body) {
				if (e || resp.statusCode !== 200) return callback(e || new Error('status'));
				callback(null, {user_id: String(body.id), nickname: body.login});
			});
		}`)
		if err != nil || m["user_id"] != "42" || m["nickname"] != "octo" {
			t.Fatalf("%v %v", m, err)
		}
	})
	t.Run("request method GET form", func(t *testing.T) {
		m, err := run(t, r, `function fetchUserProfile(accessToken, context, callback) {
			request({method: 'GET', url: '`+api.URL+`/me', headers: {Authorization: 'Bearer ' + accessToken}}, function (e, resp, body) {
				if (e) return callback(e);
				callback(null, {user_id: JSON.parse(body).login, status: resp.statusCode});
			});
		}`)
		if err != nil || m["user_id"] != "octo" || m["status"] != float64(200) {
			t.Fatalf("%v %v", m, err)
		}
	})
	for name, src := range map[string]string{
		"missing callback":   `function fetchUserProfile(a, c, cb) {}`,
		"duplicate callback": `function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'a'}); cb(null, {user_id: 'b'}); }`,
		"script error":       `function fetchUserProfile(a, c, cb) { cb(new Error('upstream-secret-detail ' + a)); }`,
		"throws":             `function fetchUserProfile(a, c, cb) { throw new Error(a); }`,
		"not defined":        `function other() {}`,
		"syntax":             `function fetchUserProfile(a, c, cb) {`,
		"post":               `function fetchUserProfile(a, c, cb) { request({method: 'POST', url: 'https://x.example'}, cb); }`,
		"require":            `function fetchUserProfile(a, c, cb) { require('net'); }`,
		"dynamic import":     `function fetchUserProfile(a, c, cb) { import('node:net').then(() => cb(null, {user_id: 'x'}), (e) => cb(e)); }`,
		"fetch":              `function fetchUserProfile(a, c, cb) { fetch('https://x.example').then(() => cb(null, {user_id: 'x'}), (e) => cb(e)); }`,
		"process":            `function fetchUserProfile(a, c, cb) { cb(null, {user_id: String(process.env)}); }`,
		"eval":               `function fetchUserProfile(a, c, cb) { cb(null, {user_id: eval('1')}); }`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := run(t, r, src)
			if !errors.Is(err, ErrScript) {
				t.Fatalf("err %v", err)
			}
			if strings.Contains(err.Error(), "upstream-access-token") || strings.Contains(err.Error(), "upstream-secret-detail") {
				t.Fatalf("raw script detail leaked: %v", err)
			}
		})
	}
	t.Run("constructor escape still cannot reach the network", func(t *testing.T) {
		_, err := run(t, r, `function fetchUserProfile(a, c, cb) {
			const p = this.constructor.constructor('return process')();
			const net = p.getBuiltinModule('node:net');
			const s = net.connect(80, '1.1.1.1');
			s.on('error', (e) => cb(null, {user_id: e.code || 'error'}));
			s.on('connect', () => cb(null, {user_id: 'connected'}));
		}`)
		// Code generation from strings is disabled; even if it were not,
		// the permission model denies the socket.
		if err == nil {
			t.Fatal("escape attempt produced a profile")
		}
	})
	t.Run("timeout", func(t *testing.T) {
		short, err := NewRunner(Config{Deadline: 300 * time.Millisecond}, NewBroker(loopbackClient()))
		if err != nil {
			t.Fatal(err)
		}
		defer short.Close()
		start := time.Now()
		_, err = run(t, short, `function fetchUserProfile(a, c, cb) { while (true) {} }`)
		if !errors.Is(err, ErrTimeout) || time.Since(start) > 3*time.Second {
			t.Fatalf("err %v after %v", err, time.Since(start))
		}
	})
	t.Run("cancellation releases the slot", func(t *testing.T) {
		one, _ := NewRunner(Config{PerTenant: 1}, NewBroker(loopbackClient()))
		defer one.Close()
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, err := one.Execute(ctx, Request{TenantID: "t", Source: `function fetchUserProfile(a, c, cb) { setTimeout(() => {}, 100000); }`})
			done <- err
		}()
		time.Sleep(200 * time.Millisecond)
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
		if _, err := run(t, one, `function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'after'}); }`); err != nil {
			t.Fatalf("slot not released: %v", err)
		}
	})
	t.Run("tenant concurrency limit", func(t *testing.T) {
		lim, _ := NewRunner(Config{PerTenant: 2}, NewBroker(loopbackClient()))
		defer lim.Close()
		var mu sync.Mutex
		active, peak := 0, 0
		lim.onStart = func() { mu.Lock(); active++; peak = max(peak, active); mu.Unlock() }
		lim.onEnd = func() { mu.Lock(); active--; mu.Unlock() }
		var wg sync.WaitGroup
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = lim.Execute(context.Background(), Request{TenantID: "t", Source: `function fetchUserProfile(a, c, cb) { setTimeout(() => cb(null, {user_id: 'x'}), 150); }`})
			}()
		}
		wg.Wait()
		if peak > 2 {
			t.Fatalf("peak %d executions for one tenant", peak)
		}
	})
	t.Run("no cross-execution leakage", func(t *testing.T) {
		_, _ = run(t, r, `globalThis.leak = 'secret'; function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'x'}); }`)
		m, err := run(t, r, `function fetchUserProfile(a, c, cb) { cb(null, {user_id: typeof leak}); }`)
		if err != nil || m["user_id"] != "undefined" {
			t.Fatalf("%v %v", m, err)
		}
	})
	t.Run("oversized output", func(t *testing.T) {
		_, err := run(t, r, `function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'x', pad: 'y'.repeat(200000)}); }`)
		if !errors.Is(err, ErrScript) && !errors.Is(err, ErrProtocol) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestRunnerUnavailable(t *testing.T) {
	r, err := NewRunner(Config{Node: "/nonexistent/node"}, NewBroker(loopbackClient()))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Probe(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("probe %v", err)
	}
	if _, err := r.Execute(context.Background(), Request{TenantID: "t", Source: "function fetchUserProfile(a,c,cb){cb(null,{user_id:'x'})}"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("execute %v", err)
	}
	for _, v := range []string{"v22.13.0", "v24.9.0", "garbage"} {
		if checkNodeVersion(v) == nil {
			t.Errorf("version %s accepted", v)
		}
	}
	if checkNodeVersion("v25.0.0") != nil || checkNodeVersion("v26.8.1") != nil {
		t.Error("supported version rejected")
	}
}
