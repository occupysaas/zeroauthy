// internal/oauth/fixture_test.go
package oauth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const fixtureSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    default_audience: https://api.acme.test
    resource_servers:
      - identifier: https://api.acme.test
        name: Acme API
        token_lifetime: 3600
        scopes: [{value: "read:things"}, {value: "write:things"}]
      - identifier: https://billing.acme.test
        name: Billing
        scopes: [{value: "read:invoices"}]
    clients:
      - {client_id: m2m, app_type: non_interactive, client_secret: m2m-secret, grant_types: [client_credentials]}
      - {client_id: m2m-basic, app_type: non_interactive, client_secret: "p@ss:w+rd", token_endpoint_auth_method: client_secret_basic, grant_types: [client_credentials]}
      - {client_id: web, app_type: regular_web, client_secret: web-secret, grant_types: [authorization_code]}
      - {client_id: spa, app_type: spa, grant_types: [client_credentials]}
    client_grants:
      - {client_id: m2m, audience: https://api.acme.test, scopes: ["read:things", "write:things"]}
      - {client_id: m2m-basic, audience: https://api.acme.test, scopes: ["read:things"]}
      - {client_id: spa, audience: https://api.acme.test, scopes: ["read:things"]}
  - name: globex
    domains: [globex.example.test]
    resource_servers:
      - {identifier: https://api.globex.test, name: Globex API, scopes: [{value: "read:things"}]}
    clients:
      - {client_id: globex-m2m, app_type: non_interactive, client_secret: globex-secret, grant_types: [client_credentials]}
    client_grants:
      - {client_id: globex-m2m, audience: https://api.globex.test, scopes: ["read:things"]}
`

type fixture struct {
	st   store.Store
	keys *keys.Manager
	h    *Handlers
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st := memory.New()
	f, err := seed.Parse([]byte(fixtureSeed))
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Apply(context.Background(), st, f, fixedNow); err != nil {
		t.Fatal(err)
	}
	km := newTestKeys(t)
	tenants, _ := st.Tenants().List(context.Background())
	for _, tn := range tenants {
		if err := km.Ensure(context.Background(), tn.ID); err != nil {
			t.Fatal(err)
		}
	}
	return &fixture{st: st, keys: km, h: &Handlers{Store: st, Now: fixedNow, Minter: &Minter{Keys: km, Now: fixedNow}}}
}

// server returns the token endpoint behind tenant resolution and contract
// validation. Use strict=false for tests that send malformed requests.
func (f *fixture) server(t *testing.T, strict bool) http.Handler {
	h := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthToken))
	if strict {
		return contract.Wrap(t, h)
	}
	return contract.WrapResponses(t, h)
}

func (f *fixture) tenantID(t *testing.T, name string) string {
	t.Helper()
	tn, err := f.st.Tenants().GetByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return tn.ID
}
