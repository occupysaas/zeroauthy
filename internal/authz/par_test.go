package authz

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// push stores a pushed request the way /oauth/par does and returns its
// request_uri.
func (e *env) push(t *testing.T, tenantID, clientID string, params map[string]string, expiresIn time.Duration) string {
	t.Helper()
	id := secrets.RandomString(43)
	p := map[string]string{"client_id": clientID}
	for k, v := range params {
		p[k] = v
	}
	if err := e.st.PushedAuthRequests().Create(context.Background(), &store.PushedAuthRequest{
		TenantID: tenantID, IDHash: secrets.HashToken(id), ClientID: clientID, Params: p,
		ExpiresAt: fixedNow().Add(expiresIn), CreatedAt: fixedNow(),
	}); err != nil {
		t.Fatal(err)
	}
	return RequestURIPrefix + id
}

func parParams() map[string]string {
	return map[string]string{
		"redirect_uri": "https://par.acme.test/cb", "response_type": "code",
		"scope": "openid", "state": "pushed-state", "za_pushed": "1",
	}
}

func parQuery(clientID, uri string) url.Values {
	return url.Values{"client_id": {clientID}, "request_uri": {uri}}
}

func TestPushedRequestStartsLogin(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	loc := location(t, e.get(t, parQuery("par-web", uri)))
	if loc.Path != "/u/login" {
		t.Fatalf("Location = %s", loc)
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	if txn.Params["state"] != "pushed-state" || txn.Params["redirect_uri"] != "https://par.acme.test/cb" {
		t.Fatalf("transaction params = %v", txn.Params)
	}
}

func TestPushedRequestWithSessionIssuesCode(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	loc := location(t, e.get(t, parQuery("par-web", uri), e.login(t, fixedNow())))
	if loc.Host != "par.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "pushed-state" {
		t.Fatalf("Location = %s", loc)
	}
}

// A pushed request may be used with POST /authorize as well.
func TestPushedRequestByPost(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	loc := location(t, e.post(t, parQuery("par-web", uri), e.login(t, fixedNow())))
	if loc.Host != "par.acme.test" || loc.Query().Get("code") == "" || loc.Query().Get("state") != "pushed-state" {
		t.Fatalf("Location = %s", loc)
	}
}

// P1: SDKs add their own parameters next to request_uri; only the pushed
// ones count.
func TestPushedExtrasAreIgnored(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	q := parQuery("par-web", uri)
	q.Set("state", "query-state")
	q.Set("redirect_uri", "https://par.acme.test/cb2")
	q.Set("response_type", "token")
	q.Set("scope", "openid email")
	q.Set("foo", "bar")
	loc := location(t, e.get(t, q, e.login(t, fixedNow())))
	if loc.Path != "/cb" || loc.Query().Get("state") != "pushed-state" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
}

func TestPushedReuseFails(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	location(t, e.get(t, parQuery("par-web", uri)))
	rec := e.get(t, parQuery("par-web", uri))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("reuse: status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// D-0029: a wrong-client attempt by an existing client uses the request up.
func TestWrongClientUsesUpRequest(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime)
	for _, client := range []string{"web", "par-web"} {
		rec := e.get(t, parQuery(client, uri))
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Fatalf("client %s: status %d, Location %q", client, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestPushedRequestRefused(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func() url.Values{
		"expired": func() url.Values {
			return parQuery("par-web", e.push(t, e.tenant.ID, "par-web", parParams(), 0))
		},
		"other client": func() url.Values {
			return parQuery("web", e.push(t, e.tenant.ID, "par-web", parParams(), PARLifetime))
		},
		"unknown":      func() url.Values { return parQuery("par-web", RequestURIPrefix+"nope") },
		"wrong prefix": func() url.Values { return parQuery("par-web", "urn:example:nope") },
		"no client_id": func() url.Values { return url.Values{"request_uri": {RequestURIPrefix + "x"}} },
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.get(t, q())
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
				t.Fatalf("status %d, Location %q, body %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
		})
	}
}

// P6b: a tenant without PAR refuses request_uri.
func TestPushedRequestOnTenantWithoutPAR(t *testing.T) {
	e := newEnv(t)
	globex, err := e.st.Tenants().GetByName(context.Background(), "globex")
	if err != nil {
		t.Fatal(err)
	}
	uri := e.push(t, globex.ID, "globex-spa", map[string]string{
		"redirect_uri": "https://app.globex.test/cb", "response_type": "code", "za_pushed": "1",
	}, PARLifetime)
	r := httptestRequest("https://globex.example.test/authorize?" + parQuery("globex-spa", uri).Encode())
	rec := e.serve(t, r)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// P5: a client that requires PAR cannot use a plain request.
func TestRequiredPARRefusesPlainRequest(t *testing.T) {
	e := newEnv(t)
	q := url.Values{
		"client_id": {"par-required"}, "redirect_uri": {"https://req.acme.test/cb"},
		"response_type": {"code"}, "scope": {"openid"}, "state": {"s1"},
	}
	loc := location(t, e.get(t, q))
	if loc.Host != "req.acme.test" || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "s1" {
		t.Fatalf("Location = %s", loc)
	}
}

// Review focus 2: the pushed mark survives the login transaction, so Resume
// does not refuse a client that requires PAR.
func TestRequiredPARSurvivesLogin(t *testing.T) {
	e := newEnv(t)
	uri := e.push(t, e.tenant.ID, "par-required", map[string]string{
		"redirect_uri": "https://req.acme.test/cb", "response_type": "code", "scope": "openid", "za_pushed": "1",
	}, PARLifetime)
	loc := location(t, e.get(t, parQuery("par-required", uri)))
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	req := RequestFromParams(txn.Params)
	if !req.Pushed {
		t.Fatalf("transaction lost the pushed mark: %v", txn.Params)
	}
	if _, verr, _ := ValidateRequest(context.Background(), e.st, e.tenant, &req); verr != nil {
		t.Fatalf("revalidation failed: %+v", verr)
	}
}

// Review focus 5.
func TestExtParamsRoundTrip(t *testing.T) {
	req := ParseRequest(url.Values{"client_id": {"c"}, "ext-tenant_hint": {"blue"}, "foo": {"bar"}})
	req.Pushed = true
	p := req.Params()
	if p["ext-tenant_hint"] != "blue" || p["za_pushed"] != "1" || p["foo"] != "" {
		t.Fatalf("Params = %v", p)
	}
	p["za_stage"] = "consent"
	back := RequestFromParams(p)
	if back.Ext["ext-tenant_hint"] != "blue" || !back.Pushed || len(back.Ext) != 1 {
		t.Fatalf("RequestFromParams = %+v", back)
	}
	// A pushed mark never comes from a browser query.
	if ParseRequest(url.Values{"za_pushed": {"1"}}).Pushed {
		t.Fatal("ParseRequest accepted za_pushed from a query")
	}
	if !strings.HasPrefix(RequestURIPrefix, "urn:ietf:params:oauth:request_uri:") || MaxExtParams != 10 || PARLifetime != 30*time.Second {
		t.Fatal("PAR constants changed")
	}
}

// The stored binding wins over a client_id inside the pushed params.
func TestPushedClientIDComesFromBinding(t *testing.T) {
	e := newEnv(t)
	id := secrets.RandomString(43)
	if err := e.st.PushedAuthRequests().Create(context.Background(), &store.PushedAuthRequest{
		TenantID: e.tenant.ID, IDHash: secrets.HashToken(id), ClientID: "par-web",
		Params: map[string]string{
			"client_id": "web", "redirect_uri": "https://par.acme.test/cb", "response_type": "code",
			"scope": "openid", "za_pushed": "1",
		},
		ExpiresAt: fixedNow().Add(PARLifetime), CreatedAt: fixedNow(),
	}); err != nil {
		t.Fatal(err)
	}
	loc := location(t, e.get(t, parQuery("par-web", RequestURIPrefix+id), e.login(t, fixedNow())))
	if loc.Host != "par.acme.test" || loc.Query().Get("code") == "" {
		t.Fatalf("Location = %s", loc)
	}
}
