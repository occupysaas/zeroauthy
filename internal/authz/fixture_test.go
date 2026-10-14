package authz

import (
	"context"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC) }

const fixtureSeed = `
tenants:
  - name: acme
    domains: [acme.example.test]
    resource_servers:
      - {identifier: "https://api.acme.test", name: API, scopes: [{value: "read:things"}]}
    clients:
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.acme.test/callback", "https://*.preview.acme.test/cb", "http://localhost:3000/"]
        web_origins: ["https://app.acme.test"]
      - client_id: web
        app_type: regular_web
        client_secret: web-secret
        grant_types: [authorization_code]
        callbacks: ["https://web.acme.test/cb"]
      - client_id: m2m
        app_type: non_interactive
        client_secret: m2m-secret
        grant_types: [client_credentials]
        callbacks: ["https://m2m.acme.test/cb"]
    connections:
      - {name: Username-Password-Authentication, enabled_clients: [spa, web]}
      - {name: Other-DB, enabled_clients: [web]}
    users:
      - {connection: Username-Password-Authentication, email: alice@acme.test, password: "alice password 1", email_verified: true}
  - name: globex
    domains: [globex.example.test]
    clients:
      - {client_id: globex-spa, app_type: spa, grant_types: [authorization_code], callbacks: ["https://app.globex.test/cb"]}
`

type fixture struct {
	st     store.Store
	tenant *store.Tenant
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
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, tenant: tn}
}
