package authz

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// codeCounter counts authorization codes created through the handlers.
type codeCounter struct {
	store.Store
	n *int
}

func (s codeCounter) AuthCodes() store.AuthCodes { return countedCodes{s.Store.AuthCodes(), s.n} }

type countedCodes struct {
	store.AuthCodes
	n *int
}

func (c countedCodes) Create(ctx context.Context, ac *store.AuthCode) error {
	*c.n++
	return c.AuthCodes.Create(ctx, ac)
}

type actionsEnv struct {
	*env
	actions *actionstest.Env
	w       keys.Wrapper
	codes   int
}

func newActionsEnv(t *testing.T) *actionsEnv {
	t.Helper()
	e := newEnv(t)
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ae := &actionsEnv{env: e, actions: actionstest.New(t, e.st, w), w: w}
	e.h.Store = codeCounter{e.st, &ae.codes}
	e.h.Actions, e.h.Wrapper = ae.actions.Engine, w
	return ae
}

func (e *actionsEnv) postLogin(t *testing.T, name, body string) {
	t.Helper()
	e.actions.PostLogin(t, e.tenant.ID, name, `exports.onExecutePostLogin = async (event, api) => {
	  api.user.setAppMetadata("runs", (event.user.app_metadata.runs || 0) + 1);
	  `+body+`
	};`)
}

// runs is how many post-login flows ran for alice (each counts itself in
// app_metadata, which commits at flow end).
func (e *actionsEnv) runs(t *testing.T) float64 {
	t.Helper()
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := u.AppMetadata["runs"].(float64)
	return n
}

func (e *actionsEnv) setRedirectionPolicy(t *testing.T, clientID, policy string) {
	t.Helper()
	c, err := e.st.Clients().Get(context.Background(), e.tenant.ID, clientID)
	if err != nil {
		t.Fatal(err)
	}
	c.RedirectionPolicy = policy
	if err := e.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}

// TestActionsDenyAndErrorSurfaces: how post-login denials and failures reach
// /authorize (D-0053), and that the flow runs before consent exactly once.
func TestActionsDenyAndErrorSurfaces(t *testing.T) {
	t.Run("deny redirects access_denied with the sanitized reason", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "deny", `api.access.deny("Zugriff für Gäste gesperrt");`)
		loc := location(t, e.get(t, goodQuery(), e.login(t, fixedNow())))
		q := loc.Query()
		if loc.Host != "app.acme.test" || q.Get("error") != "access_denied" || q.Get("error_description") != "Zugriff f?r G?ste gesperrt" ||
			q.Get("state") != "st" || q.Get("code") != "" {
			t.Fatalf("Location = %s", loc)
		}
		if e.codes != 0 {
			t.Fatal("a code was created")
		}
		if e.runs(t) != 1 {
			t.Fatal("metadata set before deny was not committed")
		}
		if logs := e.actions.Logs.String(); !strings.Contains(logs, "actions flow denied") || !strings.Contains(logs, "action=deny") {
			t.Fatalf("deny not logged: %s", logs)
		}
	})

	t.Run("validation.error redirects its code", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "validate", `api.validation.error("invalid_profile", "complete your profile");`)
		q := location(t, e.get(t, goodQuery(), e.login(t, fixedNow()))).Query()
		if q.Get("error") != "invalid_profile" || q.Get("error_description") != "complete your profile" || e.codes != 0 {
			t.Fatalf("query = %v codes=%d", q, e.codes)
		}
	})

	t.Run("deny on a protected client is an error page", func(t *testing.T) {
		e := newActionsEnv(t)
		e.setRedirectionPolicy(t, "spa", store.RedirectionPolicyOpenRedirectProtection)
		e.postLogin(t, "deny", `api.access.deny("not today");`)
		rec := e.get(t, goodQuery(), e.login(t, fixedNow()))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" || !strings.Contains(rec.Body.String(), "not today") || e.codes != 0 {
			t.Fatalf("status %d Location %q body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
		}
	})

	t.Run("a thrown error is server_error without the reference", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "boom", `throw new Error("boom");`)
		q := location(t, e.get(t, goodQuery(), e.login(t, fixedNow()))).Query()
		if q.Get("error") != "server_error" || q.Get("error_description") != "internal error" || q.Get("code") != "" || e.codes != 0 {
			t.Fatalf("query = %v codes=%d", q, e.codes)
		}
		if e.runs(t) != 0 {
			t.Fatal("metadata committed by a failed flow")
		}
		if strings.Contains(q.Encode(), "exe_") {
			t.Fatal("execution ID in the redirect")
		}
	})

	t.Run("a thrown error on a protected client shows the reference", func(t *testing.T) {
		e := newActionsEnv(t)
		e.setRedirectionPolicy(t, "spa", store.RedirectionPolicyOpenRedirectProtection)
		e.postLogin(t, "boom", `throw new Error("boom");`)
		rec := e.get(t, goodQuery(), e.login(t, fixedNow()))
		body := rec.Body.String()
		i := strings.Index(body, "Reference: exe_")
		if rec.Code != http.StatusInternalServerError || rec.Header().Get("Location") != "" || i < 0 || e.codes != 0 {
			t.Fatalf("status %d body %s", rec.Code, body)
		}
		ref := body[i+len("Reference: "):]
		ref = ref[:strings.IndexAny(ref, "<\n ")]
		logs := e.actions.Logs.String()
		line := ""
		for _, l := range strings.Split(logs, "\n") {
			if strings.Contains(l, "execution_id="+ref) {
				line = l
			}
		}
		for _, want := range []string{"actions flow failed", "tenant=" + e.tenant.ID, "trigger=post-login", "action=boom"} {
			if !strings.Contains(line, want) {
				t.Fatalf("log line for %s lacks %q: %q", ref, want, line)
			}
		}
	})

	t.Run("sendUserTo suspends without a code", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "redirect", `api.redirect.sendUserTo("https://example.test/");`)
		loc := location(t, e.get(t, goodQuery(), e.login(t, fixedNow())))
		if loc.Host != "example.test" || loc.Query().Get("state") == "" || e.codes != 0 || e.runs(t) != 0 {
			t.Fatalf("redirect = %s", loc)
		}
	})

	t.Run("consent lists target scopes and accepting does not re-run", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "scopes", `api.transaction.addTargetScope("write:things"); api.accessToken.addScope("admin:x");
		  api.accessToken.setCustomClaim("https://acme.test/claim", "v");`)
		e.addAPIScope(t, "write:things", "partner")
		ck := e.login(t, fixedNow())
		loc := location(t, e.get(t, partnerQuery(), ck))
		if loc.Path != "/u/consent" || e.runs(t) != 1 {
			t.Fatalf("Location = %s runs=%v", loc, e.runs(t))
		}
		txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		sess := e.session(t, ck)
		view, err := e.h.ConsentView(context.Background(), e.res(), txn, sess)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(view.Scopes, "write:things") || !slices.Contains(view.Scopes, "read:things") || slices.Contains(view.Scopes, "admin:x") {
			t.Fatalf("consent scopes = %v", view.Scopes)
		}
		if strings.Contains(txn.Params[effectsKey], "admin:x") || strings.Contains(txn.Params[effectsKey], "acme.test/claim") {
			t.Fatal("effects stored in the clear on the transaction")
		}
		// The seal is bound to this transaction.
		other := *txn
		other.ID = "another-transaction"
		if _, err := e.h.consentEffects(e.tenant.ID, &other); err == nil {
			t.Fatal("sealed effects opened on another transaction")
		}
		cl := location(t, e.consent(t, txn, ck, true))
		code := cl.Query().Get("code")
		if cl.Host != "partner.example" || code == "" {
			t.Fatalf("Location = %s", cl)
		}
		if e.runs(t) != 1 {
			t.Fatalf("accepting consent ran the flow again (runs=%v)", e.runs(t))
		}
		ac, err := e.st.AuthCodes().Get(context.Background(), e.tenant.ID, secrets.HashToken(code))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(ac.Scopes, "write:things") || slices.Contains(ac.Scopes, "admin:x") {
			t.Fatalf("code scopes = %v", ac.Scopes)
		}
		if bytes.Contains(ac.ActionEffects, []byte("admin:x")) {
			t.Fatal("effects stored in the clear on the code")
		}
		eff, err := actions.OpenEffects(e.w, e.tenant.ID, actions.SealCode, ac.ActionEffects, ac.CodeHash)
		if err != nil || !slices.Equal(eff.AddScopes, []string{"admin:x"}) || eff.AccessClaims["https://acme.test/claim"] != "v" {
			t.Fatalf("code effects = %+v, %v", eff, err)
		}
		if g := e.userGrant(t, "partner", "https://api.acme.test"); g == nil || slices.Contains(g.Scopes, "admin:x") {
			t.Fatalf("user grant = %+v", g)
		}
	})

	t.Run("declining consent issues no code", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "scopes", `api.transaction.addTargetScope("write:things");`)
		e.addAPIScope(t, "write:things", "partner")
		ck := e.login(t, fixedNow())
		loc := location(t, e.get(t, partnerQuery(), ck))
		txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		rec := e.consent(t, txn, ck, false)
		if rec.Code != http.StatusBadRequest || e.codes != 0 || e.runs(t) != 1 {
			t.Fatalf("status %d codes=%d runs=%v", rec.Code, e.codes, e.runs(t))
		}
	})

	t.Run("a denied request is not run", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "noop", ``)
		q := url.Values{"client_id": {"partner-open"}, "redirect_uri": {"https://open.example/cb"}, "response_type": {"code"},
			"audience": {"https://locked.acme.test"}, "scope": {"read:things"}, "state": {"st"}}
		lq := location(t, e.get(t, q, e.login(t, fixedNow()))).Query()
		if lq.Get("error") == "" || e.runs(t) != 0 {
			t.Fatalf("query = %v runs=%v", lq, e.runs(t))
		}
	})

	t.Run("device approval carries sealed effects; a failure shows the reference", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "dev", `api.accessToken.setCustomClaim("https://acme.test/d", 1);`)
		dc := e.pendingDevice(t)
		rec := e.continueDevice(t, dc)
		if loc := location(t, rec); loc.Path != "/device/success" {
			t.Fatalf("Location = %s", loc)
		}
		got, err := e.st.DeviceCodes().Get(context.Background(), e.tenant.ID, dc.DeviceCodeHash)
		if err != nil || got.Status != store.DeviceCodeApproved {
			t.Fatalf("device code = %+v, %v", got, err)
		}
		eff, err := actions.OpenEffects(e.w, e.tenant.ID, actions.SealDevice, got.ActionEffects, dc.DeviceCodeHash)
		if err != nil || eff.AccessClaims["https://acme.test/d"] != 1.0 {
			t.Fatalf("device effects = %+v, %v", eff, err)
		}

		e.postLogin(t, "devboom", `throw new Error("no");`)
		dc = e.pendingDevice(t)
		rec = e.continueDevice(t, dc)
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Reference: exe_") {
			t.Fatalf("status %d body %s", rec.Code, rec.Body)
		}
		if got, _ := e.st.DeviceCodes().Get(context.Background(), e.tenant.ID, dc.DeviceCodeHash); got.Status != store.DeviceCodePending {
			t.Fatalf("device code decided on failure: %s", got.Status)
		}

		e.postLogin(t, "devdeny", `api.access.deny("no");`)
		dc = e.pendingDevice(t)
		if loc := location(t, e.continueDevice(t, dc)); loc.Path != "/device/denied" {
			t.Fatalf("Location = %s", loc)
		}
	})
}

// addAPIScope defines scope on the API and adds it to clientID's user grant.
func (e *actionsEnv) addAPIScope(t *testing.T, scope, clientID string) {
	t.Helper()
	ctx := context.Background()
	rs, err := e.st.ResourceServers().GetByIdentifier(ctx, e.tenant.ID, "https://api.acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rs.Scopes = append(rs.Scopes, store.Scope{Value: scope})
	if err := e.st.ResourceServers().Update(ctx, rs); err != nil {
		t.Fatal(err)
	}
	g, err := e.st.ClientGrants().Find(ctx, e.tenant.ID, clientID, rs.Identifier, store.SubjectTypeUser)
	if err != nil {
		t.Fatal(err)
	}
	g.Scopes = append(g.Scopes, scope)
	if err := e.st.ClientGrants().Update(ctx, g); err != nil {
		t.Fatal(err)
	}
}

func (e *actionsEnv) pendingDevice(t *testing.T) *store.DeviceCode {
	t.Helper()
	hash := secrets.HashToken(secrets.RandomString(24))
	dc := &store.DeviceCode{TenantID: e.tenant.ID, DeviceCodeHash: hash, UserCodeHash: "uc-" + hash, ClientID: "tv",
		Scopes: []string{"openid"}, Status: store.DeviceCodePending, ExpiresAt: fixedNow().Add(TxnLifetime), CreatedAt: fixedNow()}
	if err := e.st.DeviceCodes().Create(context.Background(), dc); err != nil {
		t.Fatal(err)
	}
	return dc
}

func (e *actionsEnv) continueDevice(t *testing.T, dc *store.DeviceCode) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptestRequest("https://acme.example.test/activate")
	r.AddCookie(e.login(t, fixedNow()))
	e.h.ContinueDevice(rec, r, e.res(), dc, "")
	return rec
}

// TestActionsConsentMarker: a flow without token or scope effects leaves
// only a marker on the consent transaction, and accepting still does not
// run it again.
func TestActionsConsentMarker(t *testing.T) {
	e := newActionsEnv(t)
	e.postLogin(t, "meta", ``)
	ck := e.login(t, fixedNow())
	loc := location(t, e.get(t, partnerQuery(), ck))
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params[effectsKey] != ranEmpty {
		t.Fatalf("effects param = %q", txn.Params[effectsKey])
	}
	if cl := location(t, e.consent(t, txn, ck, true)); cl.Query().Get("code") == "" || e.runs(t) != 1 {
		t.Fatalf("Location = %s runs=%v", cl, e.runs(t))
	}
}

// TestActionsQueryOmitsInternalKeys: event.request.query is the
// authorization request without zeroauthy's own keys (za_pushed).
func TestActionsQueryOmitsInternalKeys(t *testing.T) {
	e := newActionsEnv(t)
	e.postLogin(t, "query", `api.user.setAppMetadata("query", Object.keys(event.request.query).sort().join(","));`)
	q := goodQuery()
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
	// A pushed request carries za_pushed in its transaction params.
	req := ParseRequest(q)
	req.Pushed = true
	if _, ok := req.Params()[pushedKey]; !ok {
		t.Fatal("test premise: pushed requests carry an internal key")
	}
	rec := httptest.NewRecorder()
	r := httptestRequest("https://acme.example.test/authorize")
	ck := e.login(t, fixedNow())
	r.AddCookie(ck)
	client, err := e.st.Clients().Get(context.Background(), e.tenant.ID, "spa")
	if err != nil {
		t.Fatal(err)
	}
	e.h.finish(rec, r, e.res(), client, flowReq{Request: req}, e.session(t, ck), nil, false, false)
	u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := u.AppMetadata["query"].(string)
	if strings.Contains(got, "za_") || !strings.Contains(got, "client_id") {
		t.Fatalf("event.request.query keys = %q", got)
	}
}

// TestActionsNoBindingsCost: without bound post-login Actions, /authorize
// costs one bindings read and no other added query.
func TestActionsNoBindingsCost(t *testing.T) {
	e := newActionsEnv(t)
	counts := &actionstest.Counts{}
	cs := actionstest.CountingStore{Store: e.st, Counts: counts}
	e.h.Store, e.actions.Engine.Store = cs, cs
	run := func(engine bool) map[string]int {
		e.h.Actions = nil
		if engine {
			e.h.Actions = e.actions.Engine
		}
		ck := e.login(t, fixedNow())
		counts.Reset()
		if loc := location(t, e.get(t, goodQuery(), ck)); loc.Query().Get("code") == "" {
			t.Fatalf("Location = %s", loc)
		}
		return counts.Snapshot()
	}
	without, with := run(false), run(true)
	want := map[string]int{}
	for k, v := range without {
		want[k] = v
	}
	want["Actions"]++
	want["Actions.Bindings"]++
	if len(with) != len(want) {
		t.Fatalf("queries with an engine and no bindings %v, want %v", with, want)
	}
	for k, v := range want {
		if with[k] != v {
			t.Fatalf("queries with an engine and no bindings %v, want %v", with, want)
		}
	}
}
