package adhub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func profileReply(claims map[string]any) any {
	return map[string]any{"profile": map[string]any{"id": claims["username"], "displayName": "User " + fmt.Sprint(claims["username"])}}
}

// TestHubMultiplexer is Review Focus 2: concurrent requests get their own
// replies; a reply for another pid or another op is never taken; late
// replies are dropped.
func TestHubMultiplexer(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	var mu sync.Mutex
	held := map[string]map[string]any{}
	c := connect(t, e, srv, k, key, func(op string, claims map[string]any) any {
		switch claims["username"] {
		case "slow":
			time.Sleep(200 * time.Millisecond)
		case "hold":
			mu.Lock()
			held[claims["pid"].(string)] = claims
			mu.Unlock()
			return nil
		}
		return profileReply(claims)
	})
	ctx := context.Background()
	// Concurrent, answered out of order.
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := fmt.Sprintf("user%d", i)
			if i%5 == 0 {
				user = "slow"
			}
			r, err := h.Call(ctx, "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": user, "password": "pw"})
			if err != nil {
				errs <- err
				return
			}
			var p struct{ ID string }
			_ = json.Unmarshal(r.Profile, &p)
			if p.ID != user {
				errs <- fmt.Errorf("request for %s got %s", user, p.ID)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	// The connector saw verified tokens carrying a pid and the arguments.
	for _, r := range c.requests() {
		if pid, _ := r["pid"].(string); len(pid) != 32 || r["password"] != "pw" {
			t.Fatalf("request claims %v", r)
		}
	}

	// A reply for another pid, or with another op's suffix, is ignored: the
	// request times out.
	tctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := h.Call(tctx, "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "hold"})
		done <- err
	}()
	var pid string
	waitFor(t, "held request", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for p := range held {
			pid = p
		}
		return pid != ""
	})
	send := func(name string, payload any) {
		body, _ := json.Marshal(payload)
		b, _ := json.Marshal(frame{N: name, P: body})
		_, _ = c.ws.Write(b)
	}
	send("0123456789abcdef0123456789abcdef_result", map[string]any{"profile": map[string]any{"id": "intruder"}})
	send(pid+"_list_groups_result", map[string]any{"groups": []string{"admins"}})
	send(pid+"_change_password_result", map[string]any{"profile": map[string]any{"id": "intruder"}})
	send("garbage", nil)
	_, _ = c.ws.Write([]byte("not json"))
	if err := <-done; !errors.Is(err, ErrTimeout) {
		t.Fatalf("mismatched replies taken: %v", err)
	}
	// The late, correctly addressed reply is dropped without effect.
	send(pid+"_result", map[string]any{"profile": map[string]any{"id": "late"}})
	// The socket still serves.
	if r, err := h.Call(ctx, "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "after"}); err != nil || r.Profile == nil {
		t.Fatalf("after late reply: %v", err)
	}
	if h.inFlight[connKey{"ten_a", e.conn.ID}] != 0 {
		t.Fatalf("in-flight count leaked: %d", h.inFlight[connKey{"ten_a", e.conn.ID}])
	}
}

// At most MaxInFlight requests per connection wait for a connector.
func TestHubInFlightCap(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	connect(t, e, srv, k, key, func(string, map[string]any) any { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range MaxInFlight {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.Call(ctx, "ten_a", e.conn.ID, OpListGroups, map[string]any{})
		}()
	}
	waitFor(t, "requests in flight", func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.inFlight[connKey{"ten_a", e.conn.ID}] == MaxInFlight
	})
	if _, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpListGroups, map[string]any{}); !errors.Is(err, ErrBusy) {
		t.Fatalf("over the cap: %v", err)
	}
	// Another connection is not affected by this one's cap.
	if _, err := h.Call(context.Background(), "ten_b", e.connB.ID, OpListGroups, map[string]any{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("other connection: %v", err)
	}
	cancel()
	wg.Wait()
}

// A disconnect fails pending requests at once; with two connectors the
// request fails over to the other; with none the connection is unavailable.
func TestHubDisconnectAndFailover(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	if _, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "u"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no connector: %v", err)
	}
	k1, k2 := newConnectorKey(t, 2048), newConnectorKey(t, 2048)
	key := register(t, e, k1)
	register(t, e, k2)
	silent := connect(t, e, srv, k1, key, func(string, map[string]any) any { return nil })
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "u"})
		done <- err
	}()
	waitFor(t, "request sent", func() bool { return len(silent.requests()) == 1 })
	silent.ws.Close()
	if err := <-done; !errors.Is(err, ErrUnavailable) || time.Since(start) > 5*time.Second {
		t.Fatalf("pending request after disconnect: %v after %v", err, time.Since(start))
	}
	waitFor(t, "detached", func() bool { return !h.Connected("ten_a", e.conn.ID) })

	// Two connectors: a dead one is skipped.
	connect(t, e, srv, k1, key, func(_ string, c map[string]any) any { return profileReply(c) })
	connect(t, e, srv, k2, key, func(_ string, c map[string]any) any { return profileReply(c) })
	waitFor(t, "two connectors", func() bool { return len(h.localAgents(connKey{"ten_a", e.conn.ID})) == 2 })
	agents := h.localAgents(connKey{"ten_a", e.conn.ID})
	agents[0].close()
	for range 4 {
		if r, err := h.Call(context.Background(), "ten_a", e.conn.ID, OpAuthenticateUser, map[string]any{"username": "u"}); err != nil || r.Profile == nil {
			t.Fatalf("failover: %v", err)
		}
	}
}

// The request API maps connector errors (LR38a-9) and returns groups.
func TestServiceRequests(t *testing.T) {
	e := newEnv(t)
	h := newHub(e)
	srv := hubServer(t, e, h, e.ta)
	k := newConnectorKey(t, 2048)
	key := register(t, e, k)
	connect(t, e, srv, k, key, func(op string, c map[string]any) any {
		switch op {
		case string(OpListGroups):
			return map[string]any{"groups": []string{"users", "administrators"}}
		case string(OpChangePassword):
			if c["password"] == "weak" {
				return map[string]any{"err": map[string]any{"name": "PasswordComplexityError", "message": "Password doesn’t meet minimum requirements"}}
			}
			return map[string]any{"profile": map[string]any{"id": c["username"]}}
		}
		switch c["username"] {
		case "jdoe":
			if c["password"] == "right" && c["escaped"] == false {
				return profileReply(c)
			}
			return map[string]any{"err": map[string]any{"name": "WrongPassword", "message": "Wrong password"}, "profile": map[string]any{"id": "jdoe"}}
		case "locked":
			return map[string]any{"err": map[string]any{"name": "AccountLocked"}}
		case "expired":
			return map[string]any{"err": map[string]any{"name": "PasswordExpired"}}
		case "weird":
			return map[string]any{"err": map[string]any{"message": "Unexpected Error"}}
		}
		return map[string]any{"err": map[string]any{"name": "WrongUsername"}, "profile": map[string]any{"username": c["username"]}}
	})
	ctx := context.Background()
	if p, err := e.svc.Authenticate(ctx, e.conn, "jdoe", "right"); err != nil || len(p) == 0 {
		t.Fatalf("authenticate: %v", err)
	}
	for user, want := range map[string]error{"jdoe": ErrWrongCredentials, "nobody": ErrWrongCredentials, "locked": ErrAccountBlocked,
		"expired": ErrPasswordChangeRequired, "weird": ErrUnavailable} {
		if p, err := e.svc.Authenticate(ctx, e.conn, user, "wrong"); !errors.Is(err, want) || p != nil {
			t.Errorf("%s: %v (profile %s)", user, err, p)
		}
	}
	if g, err := e.svc.ListGroups(ctx, e.conn, 10); err != nil || string(g) != `["users","administrators"]` {
		t.Fatalf("groups %s %v", g, err)
	}
	if err := e.svc.ChangePassword(ctx, e.conn, "jdoe", "N3w!"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, e.conn, "jdoe", "weak"); !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("weak: %v", err)
	}
	if _, err := e.svc.Authenticate(ctx, e.connB, "jdoe", "right"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("other tenant's connection has no connector: %v", err)
	}
}
