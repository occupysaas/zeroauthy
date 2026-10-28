package actions_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/build"
	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/noderunner"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// requireNode skips without a usable Node.js (22.13+), or fails under
// ZA_REQUIRE_NODE=1.
func requireNode(t *testing.T) {
	t.Helper()
	reason := ""
	if p, err := exec.LookPath("node"); err != nil {
		reason = "node not found on PATH"
	} else if out, err := exec.Command(p, "--version").Output(); err != nil {
		reason = "node --version failed: " + err.Error()
	} else if err := noderunner.CheckNodeVersion(strings.TrimSpace(string(out))); err != nil {
		reason = err.Error()
	}
	if reason == "" {
		return
	}
	if os.Getenv("ZA_REQUIRE_NODE") == "1" {
		t.Fatalf("ZA_REQUIRE_NODE=1 but %s", reason)
	}
	t.Skip(reason)
}

// syncBuffer is a log sink safe for the runner's stderr goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type harness struct {
	t      *testing.T
	st     *memory.Store
	eng    *actions.Engine
	builds *build.Manager
	w      keys.Wrapper
	logs   *syncBuffer
	buildM map[string]string // tenant → built empty-deps build ID

	mu  sync.Mutex
	now time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	requireNode(t)
	ctx := context.Background()
	st := memory.New()
	for _, id := range []string{"t1", "t2"} {
		if err := st.Tenants().Create(ctx, &store.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
		if err := st.Users().Create(ctx, &store.User{TenantID: id, UserID: "auth0|u1", Email: "u1@example.com",
			AppMetadata: map[string]any{"plan": "free"}, UserMetadata: map[string]any{}, LoginsCount: 3,
			Identities: []store.Identity{{Connection: "db", Provider: "auth0", UserID: "u1"}}}); err != nil {
			t.Fatal(err)
		}
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := config.Actions{CacheDir: t.TempDir(), IdleTimeout: time.Minute}
	builds, err := build.New(cfg, st, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(builds.Close)
	pool, err := actions.NewRunner(cfg, builds, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, builds: builds, w: w, logs: logs, buildM: map[string]string{},
		now: time.Now().UTC().Truncate(time.Millisecond)}
	h.eng = &actions.Engine{Store: st, Runner: pool, Builds: builds, Secrets: w, Log: log, Now: h.clock}
	return h
}

func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

// built returns the tenant's built empty dependency set.
func (h *harness) built(tenantID string) string {
	h.t.Helper()
	if id, ok := h.buildM[tenantID]; ok {
		return id
	}
	id, err := h.builds.Queue(context.Background(), tenantID, nil, actionsrules.Runtime)
	if err != nil {
		h.t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		b, err := h.st.Actions().GetBuild(context.Background(), tenantID, id)
		if err != nil {
			h.t.Fatal(err)
		}
		if b.Status == store.BuildBuilt {
			break
		}
		if b.Status == store.BuildFailed || time.Now().After(deadline) {
			h.t.Fatalf("empty build: %+v", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.buildM[tenantID] = id
	return id
}

// action creates (and unless draft is set, deploys) an Action.
func (h *harness) action(tenantID, trigger, name, code string, secrets map[string]string, draft bool) *store.Action {
	h.t.Helper()
	ctx := context.Background()
	a := &store.Action{TenantID: tenantID, ID: "act_" + name, Name: name, Trigger: trigger, Runtime: actionsrules.Runtime,
		Code: code, DraftBuildID: h.built(tenantID)}
	for k, v := range secrets {
		sealed, err := keys.SealActionSecret(h.w, tenantID, a.ID, k, v)
		if err != nil {
			h.t.Fatal(err)
		}
		a.Secrets = append(a.Secrets, store.ActionSecret{Name: k, Sealed: sealed})
	}
	if err := h.st.Actions().CreateAction(ctx, a); err != nil {
		h.t.Fatal(err)
	}
	if !draft {
		h.redeploy(a, code)
	}
	return a
}

// redeploy saves code as the draft and deploys it.
func (h *harness) redeploy(a *store.Action, code string) {
	h.t.Helper()
	ctx := context.Background()
	cur, err := h.st.Actions().GetAction(ctx, a.TenantID, a.ID)
	if err != nil {
		h.t.Fatal(err)
	}
	cur.Code = code
	if err := h.st.Actions().UpdateAction(ctx, cur); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.st.Actions().Deploy(ctx, a.TenantID, a.ID, ""); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) bind(tenantID, trigger string, as ...*store.Action) {
	h.t.Helper()
	var b []store.Binding
	for _, a := range as {
		b = append(b, store.Binding{ActionID: a.ID, DisplayName: a.Name})
	}
	if _, err := h.st.Actions().ReplaceBindings(context.Background(), tenantID, trigger, b); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) user(tenantID string) *store.User {
	h.t.Helper()
	u, err := h.st.Users().Get(context.Background(), tenantID, "auth0|u1")
	if err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) loginInput(tenantID string) actions.PostLoginInput {
	return actions.PostLoginInput{
		Tenant:          tenant.Resolved{Tenant: &store.Tenant{ID: tenantID, Name: tenantID}, Host: tenantID + ".example.test"},
		Client:          &store.Client{TenantID: tenantID, ClientID: "cli1", Name: "App"},
		User:            h.user(tenantID),
		Connection:      &store.Connection{TenantID: tenantID, ID: "con_db", Name: "db", Strategy: "auth0"},
		Request:         actions.RequestInfo{IP: "203.0.113.9", Method: "GET", UserAgent: "test", Query: map[string]any{"q": "1"}},
		Protocol:        "oidc-basic-profile",
		RequestedScopes: []string{"openid", "profile"},
		TargetScopes:    []string{"read:a"},
		ResourceServer:  &store.ResourceServer{Identifier: "https://api.example.test/"},
	}
}

func (h *harness) postLogin(tenantID string) (*actions.Result, error) {
	return h.eng.PostLogin(context.Background(), h.loginInput(tenantID))
}

func (h *harness) mustPostLogin(tenantID string) *actions.Result {
	h.t.Helper()
	r, err := h.postLogin(tenantID)
	if err != nil {
		h.t.Fatalf("PostLogin: %v", err)
	}
	return r
}

func (h *harness) execution(tenantID, id string) *store.Execution {
	h.t.Helper()
	e, err := h.st.Actions().GetExecution(context.Background(), tenantID, id)
	if err != nil {
		h.t.Fatalf("execution %q: %v", id, err)
	}
	return e
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const trigLogin = "post-login"
const trigM2M = "credentials-exchange"

// TestEngineOrderAndDeny: bound Actions run in order, later Actions see
// earlier effects, a deny stops the flow and metadata set before it commits.
func TestEngineOrderAndDeny(t *testing.T) {
	h := newHarness(t)
	a1 := h.action("t1", trigLogin, "first", `exports.onExecutePostLogin = async (event, api) => {
	  api.user.setAppMetadata("plan", "pro");
	  api.user.setUserMetadata("color", "blue");
	  api.accessToken.setCustomClaim("https://x.test/one", 1);
	  api.idToken.setCustomClaim("https://x.test/id", event.user.email);
	  api.transaction.addTargetScope("write:b");
	  api.transaction.setMetadata("step", "one");
	  api.accessToken.addScope("extra");
	};`, nil, false)
	a2 := h.action("t1", trigLogin, "second", `exports.onExecutePostLogin = async (event, api) => {
	  api.accessToken.setCustomClaim("https://x.test/seen", {
	    plan: event.user.app_metadata.plan, step: event.transaction.metadata.step,
	    targets: event.transaction.target_scopes, protocol: event.transaction.protocol,
	    logins: event.stats.logins_count, ip: event.request.ip, client: event.client.client_id,
	    tenant: event.tenant.id, conn: event.connection.name, api: event.resource_server.identifier,
	  });
	};`, nil, false)
	h.bind("t1", trigLogin, a1, a2)

	r := h.mustPostLogin("t1")
	if r.Denied != nil || r.ExecutionID == "" {
		t.Fatalf("result = %+v", r)
	}
	seen := mustJSON(t, r.Effects.AccessClaims["https://x.test/seen"])
	want := `{"api":"https://api.example.test/","client":"cli1","conn":"db","ip":"203.0.113.9","logins":3,"plan":"pro","protocol":"oidc-basic-profile","step":"one","targets":["read:a","write:b"],"tenant":"t1"}`
	if seen != want {
		t.Fatalf("second Action saw %s\nwant %s", seen, want)
	}
	if r.Effects.IDClaims["https://x.test/id"] != "u1@example.com" || r.Effects.Target == nil ||
		strings.Join(r.Effects.Target.Scopes, " ") != "read:a write:b" || strings.Join(r.Effects.AddScopes, " ") != "extra" {
		t.Fatalf("effects = %+v target=%+v", r.Effects, r.Effects.Target)
	}
	if u := h.user("t1"); u.AppMetadata["plan"] != "pro" || u.UserMetadata["color"] != "blue" {
		t.Fatalf("metadata not committed: %+v %+v", u.AppMetadata, u.UserMetadata)
	}
	if e := h.execution("t1", r.ExecutionID); e.Trigger != trigLogin || len(e.Results) != 2 || e.Results[0].ActionName != "first" || e.Results[1].ActionName != "second" {
		t.Fatalf("execution = %+v", e)
	}

	// A deny in the second of three stops the flow; the first's metadata
	// commits and the third never runs.
	d1 := h.action("t1", trigLogin, "d1", `exports.onExecutePostLogin = async (event, api) => { api.user.setAppMetadata("denied_once", true); };`, nil, false)
	d2 := h.action("t1", trigLogin, "d2", `exports.onExecutePostLogin = async (event, api) => { api.access.deny("not today"); };`, nil, false)
	d3 := h.action("t1", trigLogin, "d3", `exports.onExecutePostLogin = async (event, api) => { api.user.setAppMetadata("third", true); };`, nil, false)
	h.bind("t1", trigLogin, d1, d2, d3)
	r = h.mustPostLogin("t1")
	if r.Denied == nil || r.Denied.Code != "access_denied" || r.Denied.Reason != "not today" || r.ExecutionID == "" {
		t.Fatalf("deny result = %+v", r)
	}
	u := h.user("t1")
	if u.AppMetadata["denied_once"] != true || u.AppMetadata["third"] != nil {
		t.Fatalf("app_metadata after deny = %+v", u.AppMetadata)
	}
	if e := h.execution("t1", r.ExecutionID); len(e.Results) != 2 {
		t.Fatalf("execution after deny = %+v", e)
	}
	if !strings.Contains(h.logs.String(), r.ExecutionID) {
		t.Fatalf("denied flow not logged with its execution ID:\n%s", h.logs.String())
	}

	// validation.error denies with its code and message.
	v := h.action("t1", trigLogin, "val", `exports.onExecutePostLogin = async (event, api) => { api.user.setUserMetadata("v", 1); api.validation.error("invalid_email", "Use a work address"); };`, nil, false)
	h.bind("t1", trigLogin, v)
	r = h.mustPostLogin("t1")
	if r.Denied == nil || r.Denied.Code != "invalid_email" || r.Denied.Reason != "Use a work address" {
		t.Fatalf("validation result = %+v", r)
	}
	if h.user("t1").UserMetadata["v"] != float64(1) {
		t.Fatal("metadata before validation.error not committed")
	}

	// No bindings: nothing runs, nothing is recorded.
	h.bind("t1", trigLogin)
	if r := h.mustPostLogin("t1"); r.ExecutionID != "" || r.Denied != nil {
		t.Fatalf("empty flow = %+v", r)
	}
}

// TestEngineFailClosed: every failure is an ErrFlow carrying an execution
// record, and no metadata commits.
func TestEngineFailClosed(t *testing.T) {
	h := newHarness(t)
	h.eng.FlowBudget = 2 * time.Second
	cases := map[string]string{
		"throw":            `throw new Error("boom");`,
		"timeout":          `await new Promise((r) => setTimeout(r, 10000));`,
		"session.revoke":   `try { api.session.revoke("x"); } catch (e) {}`,
		"multifactor":      `api.multifactor.enable("any");`,
		"prompt.render":    `try { api.prompt.render("p"); } catch (e) {}`,
		"samlResponse":     `api.samlResponse.setAttribute("a", "b");`,
		"refreshToken":     `try { api.refreshToken.revoke("r"); } catch (e) {}`,
		"bad scope":        `api.accessToken.addScope(42);`,
		"bad metadata":     `api.transaction.setMetadata("k", { nested: true });`,
		"bad claim name":   `api.accessToken.setCustomClaim("", 1);`,
		"bad deny":         `api.access.deny({ reason: "x" });`,
		"no redirect":      `api.redirect.sendUserTo("https://example.test/");`,
		"unknown method":   `api.user.setPassword("x");`,
		"encodeToken":      `api.redirect.encodeToken({});`,
		"bad app metadata": `api.user.setAppMetadata("$bad", 1);`,
		"huge claims":      `api.idToken.setCustomClaim("https://x.test/big", "x".repeat(100001));`,
		"validation code":  `api.validation.error("bad code\n", "m");`,
	}
	i := 0
	for name, body := range cases {
		i++
		t.Run(name, func(t *testing.T) {
			before := h.user("t1")
			a := h.action("t1", trigLogin, fmt.Sprintf("fail%d", i), `exports.onExecutePostLogin = async (event, api) => {
			  api.user.setAppMetadata("partial", true);
			  `+body+`
			};`, nil, false)
			after := h.action("t1", trigLogin, fmt.Sprintf("after%d", i), `exports.onExecutePostLogin = async (event, api) => { api.user.setAppMetadata("after", true); };`, nil, false)
			h.bind("t1", trigLogin, a, after)
			r, err := h.postLogin("t1")
			var fe *actions.ErrFlow
			if !errors.As(err, &fe) || r != nil {
				t.Fatalf("PostLogin = %+v, %v; want ErrFlow", r, err)
			}
			if fe.ExecutionID == "" {
				t.Fatal("no execution ID")
			}
			e := h.execution("t1", fe.ExecutionID)
			if len(e.Results) != 1 || e.Results[0].ErrorMsg == "" || e.Results[0].ErrorID == "" {
				t.Fatalf("execution = %+v", e)
			}
			wantID := map[string]string{"throw": "runtime_error", "timeout": "timeout", "session.revoke": "unsupported_api",
				"multifactor": "unsupported_api", "bad scope": "invalid_api_call", "no redirect": "redirect_not_allowed",
				"validation code": "invalid_api_call",
				"huge claims":     "claims_too_large", "unknown method": "runtime_error"}[name]
			if wantID != "" && e.Results[0].ErrorID != wantID {
				t.Fatalf("error id = %q (%s), want %q", e.Results[0].ErrorID, e.Results[0].ErrorMsg, wantID)
			}
			if !strings.Contains(h.logs.String(), fe.ExecutionID) {
				t.Fatal("failed flow not logged with its execution ID")
			}
			u := h.user("t1")
			if mustJSON(t, u.AppMetadata) != mustJSON(t, before.AppMetadata) {
				t.Fatalf("metadata committed on failure: %+v", u.AppMetadata)
			}
		})
	}
}

// TestEngineRoles: event.authorization.roles and api.roles serve the RBAC
// snapshot taken at flow start, with Auth0's paging limits.
func TestEngineRoles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var ids []string
	for i := range 120 {
		id := fmt.Sprintf("rol_%03d", i)
		if err := h.st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t1", ID: id, Name: fmt.Sprintf("role-%03d", i)}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	for _, batch := range [][]string{ids[:100], ids[100:]} {
		if err := h.st.RBAC().ChangeUserRoles(ctx, "t1", "auth0|u1", true, batch); err != nil {
			t.Fatal(err)
		}
	}
	// The first Action strips the user's roles mid-flow.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, batch := range [][]string{ids[:100], ids[100:]} {
			if err := h.st.RBAC().ChangeUserRoles(context.Background(), "t1", "auth0|u1", false, batch); err != nil {
				t.Error(err)
			}
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	a1 := h.action("t1", trigLogin, "roles1", `exports.onExecutePostLogin = async (event, api) => {
	  await fetch(`+"`"+srv.URL+"`"+`);
	  const out = { names: event.authorization.roles.length };
	  const p1 = await api.roles.getUserEffectiveRoles({ take: 100 });
	  const p2 = await api.roles.getUserEffectiveRoles({ take: 100, from: p1.next });
	  out.pages = [p1.roles.length, !!p1.next, p2.roles.length, p2.next === undefined];
	  out.first = p1.roles[0];
	  const errs = [];
	  for (const f of [() => api.roles.getUserEffectiveRoles({ take: 101 }),
	                   () => api.roles.getUserEffectiveRolesByIds(new Array(101).fill("x")),
	                   () => api.roles.getUserEffectiveRolesByNames(new Array(51).fill("x"))]) {
	    try { await f(); errs.push("ok"); } catch (e) { errs.push(e.name); }
	  }
	  out.errs = errs;
	  out.byIds = (await api.roles.getUserEffectiveRolesByIds(["rol_001", "rol_119", "nope"])).roles.map((r) => r.name);
	  out.byNames = (await api.roles.getUserEffectiveRolesByNames(["role-005"])).roles.map((r) => r.id);
	  out.groups = await api.groups.getUserGroups();
	  out.member = await api.groups.hasGroupMembership(["g"]);
	  out.rules = api.rules.wasExecuted("r");
	  api.accessToken.setCustomClaim("https://x.test/roles", out);
	};`, nil, false)
	a2 := h.action("t1", trigLogin, "roles2", `exports.onExecutePostLogin = async (event, api) => {
	  api.accessToken.setCustomClaim("https://x.test/later", [event.authorization.roles.length, (await api.roles.getUserEffectiveRoles({ take: 100 })).roles.length]);
	};`, nil, false)
	h.bind("t1", trigLogin, a1, a2)
	r := h.mustPostLogin("t1")
	got := mustJSON(t, r.Effects.AccessClaims["https://x.test/roles"])
	want := `{"byIds":["role-001","role-119"],"byNames":["rol_005"],"errs":["RangeError","RangeError","RangeError"],"first":{"description":"","id":"rol_000","name":"role-000"},"groups":{"groups":[]},"member":false,"names":120,"pages":[100,true,20,true],"rules":false}`
	if got != want {
		t.Fatalf("roles = %s\nwant %s", got, want)
	}
	if later := mustJSON(t, r.Effects.AccessClaims["https://x.test/later"]); later != `[120,100]` {
		t.Fatalf("snapshot not fixed at flow start: %s", later)
	}
	// The next flow sees the change.
	r = h.mustPostLogin("t1")
	if later := mustJSON(t, r.Effects.AccessClaims["https://x.test/later"]); later != `[0,0]` {
		t.Fatalf("next flow roles = %s", later)
	}
}

// TestEngineCache: the cache is per tenant and trigger, bounded, expiring
// and evicting.
func TestEngineCache(t *testing.T) {
	h := newHarness(t)
	read := `api.accessToken.setCustomClaim("https://x.test/cache", Object.fromEntries(["k", "ttl", "cap", "max", "big0", "big1", "big2"].concat(Array.from({ length: 25 }, (_, i) => "n" + i)).map((k) => [k, api.cache.get(k)?.value ?? null]).filter(([, v]) => v !== null)));`
	setter := h.action("t1", trigLogin, "setter", `exports.onExecutePostLogin = async (event, api) => {
	  if (event.request.query.mode === "set") {
	    api.cache.set("k", "v");
	    api.cache.set("ttl", "short", { ttl: 60000 });
	    api.cache.set("cap", "capped", { ttl: 48 * 3600 * 1000 });
	    api.cache.set("max", "abs", { expires_at: Date.now() + 1000, ttl: 3600000 });
	    const errs = [];
	    for (const f of [() => api.cache.set("x".repeat(65), "v"), () => api.cache.set("ok", "v".repeat(4097))]) {
	      try { f(); errs.push("ok"); } catch (e) { errs.push(e.name); }
	    }
	    api.idToken.setCustomClaim("https://x.test/errs", errs);
	    api.idToken.setCustomClaim("https://x.test/same", api.cache.get("k").value);
	  }
	  if (event.request.query.mode === "evict") {
	    for (let i = 0; i < 25; i++) api.cache.set("n" + i, String(i));
	  }
	  if (event.request.query.mode === "big") {
	    for (let i = 0; i < 3; i++) api.cache.set("big" + i, String(i).repeat(4000));
	  }
	  if (event.request.query.mode === "del") api.cache.delete("k");
	  `+read+`
	};`, nil, false)
	h.bind("t1", trigLogin, setter)
	run := func(tenantID, mode string) map[string]any {
		t.Helper()
		in := h.loginInput(tenantID)
		in.Request.Query = map[string]any{"mode": mode}
		r, err := h.eng.PostLogin(context.Background(), in)
		if err != nil {
			t.Fatal(err)
		}
		if mode == "set" {
			if e := mustJSON(t, r.Effects.IDClaims["https://x.test/errs"]); e != `["RangeError","RangeError"]` || r.Effects.IDClaims["https://x.test/same"] != "v" {
				t.Fatalf("set: %v", r.Effects.IDClaims)
			}
		}
		m, _ := r.Effects.AccessClaims["https://x.test/cache"].(map[string]any)
		return m
	}
	run("t1", "set")
	got := run("t1", "read")
	if got["k"] != "v" || got["ttl"] != "short" || got["cap"] != "capped" {
		t.Fatalf("cache after set = %v", got)
	}
	// Per tenant and per trigger.
	other := h.action("t2", trigLogin, "setter", setter.Code, nil, false)
	h.bind("t2", trigLogin, other)
	if got := run("t2", "read"); len(got) != 0 {
		t.Fatalf("t2 sees t1's cache: %v", got)
	}
	m2m := h.action("t1", trigM2M, "m2mcache", `exports.onExecuteCredentialsExchange = async (event, api) => { api.accessToken.setCustomClaim("https://x.test/k", api.cache.get("k")?.value ?? null); };`, nil, false)
	h.bind("t1", trigM2M, m2m)
	cr, err := h.eng.CredentialsExchange(context.Background(), h.m2mInput("t1"))
	if err != nil || cr.Effects.AccessClaims["https://x.test/k"] != nil {
		t.Fatalf("credentials-exchange sees post-login cache: %+v %v", cr, err)
	}
	// expires_at wins when earlier; ttl expires; the 24 h cap applies.
	h.advance(2 * time.Second)
	if got := run("t1", "read"); got["max"] != nil || got["ttl"] != "short" {
		t.Fatalf("after 2s: %v", got)
	}
	h.advance(2 * time.Minute)
	if got := run("t1", "read"); got["ttl"] != nil || got["k"] != "v" {
		t.Fatalf("after 2m: %v", got)
	}
	h.advance(15 * time.Minute)
	if got := run("t1", "read"); got["k"] != nil || got["cap"] != "capped" {
		t.Fatalf("after 17m (default TTL 15m): %v", got)
	}
	h.advance(24 * time.Hour)
	if got := run("t1", "read"); got["cap"] != nil {
		t.Fatalf("24 h cap not applied: %v", got)
	}
	// At most 20 entries; the oldest are evicted.
	got = run("t1", "evict")
	got = run("t1", "read")
	if len(got) != 20 || got["n0"] != nil || got["n24"] != "24" {
		t.Fatalf("after 25 sets: %d entries %v", len(got), got)
	}
	// At most 8192 bytes in total.
	run("t1", "big")
	got = run("t1", "read")
	if got["big2"] == nil || got["big0"] != nil {
		t.Fatalf("total size not bounded: %v", got)
	}
	run("t1", "set")
	run("t1", "del")
	if got := run("t1", "read"); got["k"] != nil {
		t.Fatalf("delete: %v", got)
	}
}

func (h *harness) m2mInput(tenantID string) actions.CredentialsInput {
	return actions.CredentialsInput{
		Tenant:          tenant.Resolved{Tenant: &store.Tenant{ID: tenantID, Name: tenantID}, Host: tenantID + ".example.test"},
		Client:          &store.Client{TenantID: tenantID, ClientID: "m2m", Name: "Machine"},
		ResourceServer:  &store.ResourceServer{Identifier: "https://api.example.test/"},
		Request:         actions.RequestInfo{IP: "198.51.100.1", Method: "POST", Body: map[string]any{"grant_type": "client_credentials"}},
		RequestedScopes: []string{"read:a", "write:a"},
		TargetScopes:    []string{"read:a", "write:a"},
	}
}

// TestEngineSecretsMasked: secret values never reach logs, execution
// records or test output.
func TestEngineSecretsMasked(t *testing.T) {
	h := newHarness(t)
	const secret = "sk_live_0123456789abcdef"
	code := `exports.onExecutePostLogin = async (event, api) => {
	  console.log("key is", event.secrets.API_KEY);
	  setTimeout(() => { throw new Error("late " + event.secrets.API_KEY); }, 0);
	  await new Promise((r) => setTimeout(r, 50));
	  throw new Error("failed with " + event.secrets.API_KEY);
	};`
	a := h.action("t1", trigLogin, "secretive", code, map[string]string{"API_KEY": secret}, false)
	h.bind("t1", trigLogin, a)
	_, err := h.postLogin("t1")
	var fe *actions.ErrFlow
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks the secret: %v", err)
	}
	e := h.execution("t1", fe.ExecutionID)
	if strings.Contains(e.Results[0].ErrorMsg, secret) || !strings.Contains(e.Results[0].ErrorMsg, "■■■■■■■■") {
		t.Fatalf("execution error = %q", e.Results[0].ErrorMsg)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(h.logs.String(), "late ■■■■■■■■") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	logs := h.logs.String()
	if strings.Contains(logs, secret) || !strings.Contains(logs, "late ■■■■■■■■") {
		t.Fatalf("server log:\n%s", logs)
	}

	out, err := h.eng.Test(context.Background(), "t1", a.ID, json.RawMessage(`{"user":{"user_id":"auth0|u1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), secret) || !strings.Contains(string(out), "key is ■■■■■■■■") {
		t.Fatalf("test output = %s", out)
	}
}

// TestEngineTestDryRun: the test endpoint runs the built draft, records but
// does not apply effects, writes nothing and uses real fetch.
func TestEngineTestDryRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var hits sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Store(r.URL.Path, true)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	if err := h.st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t1", ID: "rol_admin", Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.RBAC().ChangeUserRoles(ctx, "t1", "auth0|u1", true, []string{"rol_admin"}); err != nil {
		t.Fatal(err)
	}
	a := h.action("t1", trigLogin, "drafty", `exports.onExecutePostLogin = async (event, api) => {
	  const res = await (await fetch(`+"`"+srv.URL+"/probe`"+`)).json();
	  console.log("fetched", res.ok, event.user.email);
	  api.user.setAppMetadata("tested", true);
	  api.accessToken.setCustomClaim("https://x.test/roles", event.authorization.roles);
	  api.access.deny("dry");
	};`, nil, true)
	out, err := h.eng.Test(ctx, "t1", a.ID, json.RawMessage(`{"user":{"user_id":"auth0|u1","email":"x@example.test"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Commands []struct {
			Op   string            `json:"op"`
			Args []json.RawMessage `json:"args"`
		} `json:"commands"`
		Logs        []string `json:"logs"`
		Error       any      `json:"error"`
		ExecutionID string   `json:"execution_id"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var ops []string
	for _, c := range res.Commands {
		ops = append(ops, c.Op)
	}
	if strings.Join(ops, ",") != "user.setAppMetadata,accessToken.setCustomClaim,access.deny" || res.Error != nil || !strings.HasPrefix(res.ExecutionID, "exe_") {
		t.Fatalf("test output = %s", out)
	}
	if string(res.Commands[1].Args[1]) != `["admin"]` || len(res.Logs) != 1 || res.Logs[0] != "fetched true x@example.test" {
		t.Fatalf("test output = %s", out)
	}
	if _, ok := hits.Load("/probe"); !ok {
		t.Fatal("fetch did not reach the server")
	}
	if h.user("t1").AppMetadata["tested"] != nil {
		t.Fatal("test run committed metadata")
	}
	if n, _ := h.st.Actions().PurgeExecutions(ctx, time.Now().Add(time.Hour)); n != 0 {
		t.Fatalf("test run wrote %d executions", n)
	}

	// Unknown user: empty roles.
	out, err = h.eng.Test(ctx, "t1", a.ID, json.RawMessage(`{"user":{"user_id":"auth0|nobody"}}`))
	if err != nil || !strings.Contains(string(out), `"https://x.test/roles",[]`) {
		t.Fatalf("unknown user: %s %v", out, err)
	}
	// A draft redirect is recorded without suspending or writing state.
	redir := h.action("t1", trigLogin, "redirdraft", `exports.onExecutePostLogin = async (event, api) => { api.redirect.sendUserTo("https://example.test/step"); };`, nil, true)
	out, err = h.eng.Test(ctx, "t1", redir.ID, json.RawMessage(`{}`))
	if err != nil || !strings.Contains(string(out), `"op":"redirect.sendUserTo"`) || strings.Contains(string(out), `"error"`) {
		t.Fatalf("redirect draft: %s %v", out, err)
	}
	// A failing draft reports its error in the payload.
	bad := h.action("t1", trigLogin, "baddraft", `exports.onExecutePostLogin = async () => { throw new Error("nope"); };`, nil, true)
	out, err = h.eng.Test(ctx, "t1", bad.ID, json.RawMessage(`{}`))
	if err != nil || !strings.Contains(string(out), "nope") {
		t.Fatalf("failing draft: %s %v", out, err)
	}

	// A draft whose build is not built, and a missing Action.
	pending := &store.Action{TenantID: "t1", ID: "act_pending", Name: "pending", Trigger: trigLogin, Runtime: actionsrules.Runtime,
		Code: "exports.onExecutePostLogin = async () => {};", DraftBuildID: strings.Repeat("ab", 32)}
	if err := h.st.Actions().PutBuild(ctx, &store.Build{TenantID: "t1", ID: pending.DraftBuildID, Status: store.BuildPending}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Actions().CreateAction(ctx, pending); err != nil {
		t.Fatal(err)
	}
	if _, err := h.eng.Test(ctx, "t1", pending.ID, json.RawMessage(`{}`)); !errors.Is(err, actions.ErrDraftNotBuilt) {
		t.Fatalf("unbuilt draft: %v", err)
	}
	if _, err := h.eng.Test(ctx, "t1", "act_missing", json.RawMessage(`{}`)); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("missing Action: %v", err)
	}
	if _, err := h.eng.Test(ctx, "t2", a.ID, json.RawMessage(`{}`)); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("other tenant's Action: %v", err)
	}
}

// TestEngineCredentialsExchange: claims, target scopes and deny codes; no
// addScope.
func TestEngineCredentialsExchange(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigM2M, "m2m", `exports.onExecuteCredentialsExchange = async (event, api) => {
	  api.accessToken.setCustomClaim("https://x.test/c", { client: event.client.client_id, scope: event.accessToken.scope, body: event.request.body.grant_type,
	    requested: event.transaction.requested_scopes, add: typeof api.accessToken.addScope, idToken: typeof api.idToken, user: typeof api.user, api: event.resource_server.identifier });
	  api.transaction.removeTargetScope("write:a");
	  api.transaction.addTargetScope("admin");
	  if (event.request.body.deny) api.access.deny(event.request.body.deny, "go away");
	};`, nil, false)
	h.bind("t1", trigM2M, a)
	r, err := h.eng.CredentialsExchange(context.Background(), h.m2mInput("t1"))
	if err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, r.Effects.AccessClaims["https://x.test/c"])
	want := `{"add":"undefined","api":"https://api.example.test/","body":"client_credentials","client":"m2m","idToken":"undefined","requested":["read:a","write:a"],"scope":["read:a","write:a"],"user":"undefined"}`
	if got != want || r.Effects.Target == nil || strings.Join(r.Effects.Target.Scopes, " ") != "read:a admin" || r.ExecutionID == "" {
		t.Fatalf("claims = %s target = %+v", got, r.Effects.Target)
	}
	for _, code := range []string{"invalid_scope", "invalid_request", "server_error"} {
		in := h.m2mInput("t1")
		in.Request.Body = map[string]any{"grant_type": "client_credentials", "deny": code}
		r, err := h.eng.CredentialsExchange(context.Background(), in)
		if err != nil || r.Denied == nil || r.Denied.Code != code || r.Denied.Reason != "go away" {
			t.Fatalf("deny %s = %+v %v", code, r, err)
		}
	}
	in := h.m2mInput("t1")
	in.Request.Body = map[string]any{"grant_type": "client_credentials", "deny": "access_denied"}
	var fe *actions.ErrFlow
	if _, err := h.eng.CredentialsExchange(context.Background(), in); !errors.As(err, &fe) {
		t.Fatalf("undocumented deny code: %v", err)
	}
}

// TestEnginePinnedVersions: the binding list and versions are read once;
// rebinding or redeploying mid-flow does not change the running flow.
func TestEnginePinnedVersions(t *testing.T) {
	h := newHarness(t)
	var a1, a2 *store.Action
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.redeploy(a2, `exports.onExecutePostLogin = async (event, api) => { api.accessToken.setCustomClaim("https://x.test/two", "new"); };`)
		h.bind("t1", trigLogin, a1)
		w.WriteHeader(204)
	}))
	defer srv.Close()
	a1 = h.action("t1", trigLogin, "pin1", `exports.onExecutePostLogin = async (event, api) => {
	  if (event.request.query.rebind) await fetch(`+"`"+srv.URL+"`"+`);
	  api.accessToken.setCustomClaim("https://x.test/one", "ran");
	};`, nil, false)
	a2 = h.action("t1", trigLogin, "pin2", `exports.onExecutePostLogin = async (event, api) => { api.accessToken.setCustomClaim("https://x.test/two", "old"); };`, nil, false)
	h.bind("t1", trigLogin, a1, a2)
	in := h.loginInput("t1")
	in.Request.Query = map[string]any{"rebind": "1"}
	r, err := h.eng.PostLogin(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Effects.AccessClaims["https://x.test/one"] != "ran" || r.Effects.AccessClaims["https://x.test/two"] != "old" {
		t.Fatalf("claims = %v", r.Effects.AccessClaims)
	}
	r = h.mustPostLogin("t1")
	if _, ok := r.Effects.AccessClaims["https://x.test/two"]; ok {
		t.Fatalf("rebinding ignored by the next flow: %v", r.Effects.AccessClaims)
	}
}

// TestPurgeExecutions: execution records are kept 10 days.
func TestPurgeExecutions(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t1", Name: "t1"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for id, age := range map[string]time.Duration{"old": 241 * time.Hour, "recent": 239 * time.Hour} {
		at := now.Add(-age)
		if err := st.Actions().CreateExecution(ctx, &store.Execution{TenantID: "t1", ID: id, Trigger: trigLogin, Status: "final", CreatedAt: at, UpdatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := actions.PurgeExecutions(ctx, st, now); err != nil || n != 1 {
		t.Fatalf("purged %d, %v", n, err)
	}
	if _, err := st.Actions().GetExecution(ctx, "t1", "recent"); err != nil {
		t.Fatal(err)
	}
}

// TestEngineRedirectRequiresSession: an interactive engine call without a
// browser session fails closed and cannot commit metadata.
func TestEngineRedirectRequiresSession(t *testing.T) {
	h := newHarness(t)
	a1 := h.action("t1", trigLogin, "redir", `exports.onExecutePostLogin = async (event, api) => {
	  api.user.setAppMetadata("before_redirect", true);
	  api.redirect.sendUserTo("https://example.test/step", { query: { a: "1" } });
	};`, nil, false)
	a2 := h.action("t1", trigLogin, "afterredir", `exports.onExecutePostLogin = async (event, api) => { api.user.setAppMetadata("after_redirect", true); };`, nil, false)
	h.bind("t1", trigLogin, a1, a2)
	in := h.loginInput("t1")
	in.CanRedirect = true
	r, err := h.eng.PostLogin(context.Background(), in)
	var fe *actions.ErrFlow
	if !errors.As(err, &fe) || r != nil {
		t.Fatalf("PostLogin = %+v, %v", r, err)
	}
	e := h.execution("t1", fe.ExecutionID)
	if len(e.Results) != 1 || e.Results[0].ErrorID != "internal_error" {
		t.Fatalf("execution = %+v", e)
	}
	if u := h.user("t1"); u.AppMetadata["before_redirect"] != nil || u.AppMetadata["after_redirect"] != nil {
		t.Fatalf("metadata committed: %+v", u.AppMetadata)
	}
}

// failingStore fails user updates or execution writes, inside and outside
// transactions.
type failingStore struct {
	store.Store
	failUpdate, failExec bool
}

func (s failingStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(failingStore{tx, s.failUpdate, s.failExec}) })
}
func (s failingStore) Users() store.Users     { return failingUsers{s.Store.Users(), s.failUpdate} }
func (s failingStore) Actions() store.Actions { return failingActions{s.Store.Actions(), s.failExec} }

type failingUsers struct {
	store.Users
	fail bool
}

func (u failingUsers) Update(ctx context.Context, user *store.User) error {
	if u.fail {
		return errors.New("update refused")
	}
	return u.Users.Update(ctx, user)
}

type failingActions struct {
	store.Actions
	fail bool
}

func (a failingActions) CreateExecution(ctx context.Context, e *store.Execution) error {
	if a.fail {
		return errors.New("execution refused")
	}
	return a.Actions.CreateExecution(ctx, e)
}

// TestEngineCommitAtomic: metadata and the execution record commit together.
func TestEngineCommitAtomic(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "meta", `exports.onExecutePostLogin = async (event, api) => { api.user.setAppMetadata("atomic", true); };`, nil, false)
	h.bind("t1", trigLogin, a)
	var fe *actions.ErrFlow

	// The metadata write fails: no metadata, a failed execution record.
	h.eng.Store = failingStore{Store: h.st, failUpdate: true}
	if _, err := h.postLogin("t1"); !errors.As(err, &fe) {
		t.Fatalf("update failure: %v", err)
	}
	if e := h.execution("t1", fe.ExecutionID); len(e.Results) != 1 || e.Results[0].ErrorID != "internal_error" {
		t.Fatalf("execution = %+v", e)
	}
	if h.user("t1").AppMetadata["atomic"] != nil {
		t.Fatal("metadata committed")
	}

	// The record write fails: the metadata rolls back.
	h.eng.Store = failingStore{Store: h.st, failExec: true}
	if _, err := h.postLogin("t1"); !errors.As(err, &fe) {
		t.Fatalf("record failure: %v", err)
	}
	if h.user("t1").AppMetadata["atomic"] != nil {
		t.Fatal("metadata committed without its execution record")
	}

	h.eng.Store = h.st
	r := h.mustPostLogin("t1")
	if h.user("t1").AppMetadata["atomic"] != true || h.execution("t1", r.ExecutionID) == nil {
		t.Fatal("healthy store did not commit")
	}
}

// TestEngineNoUnixSockets: Node's permission model does not cover connecting
// to a unix-domain socket path, so the runner refuses path connections
// through net, tls and http (socketPath) while TCP stays open.
func TestEngineNoUnixSockets(t *testing.T) {
	h := newHarness(t)
	dir, err := os.MkdirTemp("", "za-sock") // short path: sun_path is ~108 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	unix, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := unix.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
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
	port := tcp.Addr().(*net.TCPAddr).Port
	a := h.action("t1", trigM2M, "sockets", fmt.Sprintf(`exports.onExecuteCredentialsExchange = async (event, api) => {
	  const net = require("net"), tls = require("tls"), http = require("http");
	  const sock = %q, out = {};
	  const try_ = (name, f) => { try { f(); out[name] = "allowed"; } catch (e) { out[name] = "denied"; } };
	  try_("connect", () => net.connect(sock).on("error", () => {}));
	  try_("options", () => net.createConnection({ path: sock }).on("error", () => {}));
	  try_("socket", () => new net.Socket().connect(sock).on("error", () => {}));
	  try_("tls", () => tls.connect({ path: sock }).on("error", () => {}));
	  try_("http", () => http.get({ socketPath: sock, path: "/" }).on("error", () => {}));
	  out.tcp = await new Promise((resolve) => {
	    const c = net.connect(%d, "127.0.0.1");
	    c.on("data", (d) => resolve(String(d)));
	    c.on("error", (e) => resolve(e.code));
	  });
	  api.accessToken.setCustomClaim("https://x.test/s", out);
	};`, sock, port), nil, false)
	h.bind("t1", trigM2M, a)
	r, err := h.eng.CredentialsExchange(context.Background(), h.m2mInput("t1"))
	if err != nil {
		t.Fatal(err)
	}
	got := mustJSON(t, r.Effects.AccessClaims["https://x.test/s"])
	want := `{"connect":"denied","http":"denied","options":"denied","socket":"denied","tcp":"tcp","tls":"denied"}`
	if got != want {
		t.Fatalf("results = %s, want %s", got, want)
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("unix socket accepted %d connections", n)
	}
}
