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
    pushed_authorization_requests_supported: true
    enabled_locales: [en, fr]
    custom_text:
      zeroauthy:
        fr:
          error:
            invalid-request: "La demande de l'application n'a pas pu aboutir."
          form-post:
            buttonText: "Poursuivre"
    resource_servers:
      - {identifier: "https://api.acme.test", skip_consent_for_verifiable_first_party_clients: true, name: API, scopes: [{value: "read:things"}]}
      - {identifier: "https://locked.acme.test", name: Locked, subject_type_authorization: {user: {policy: deny_all}}, scopes: [{value: "read:things"}]}
    client_grants:
      - {client_id: partner, audience: "https://api.acme.test", subject_type: user, scopes: ["read:things"]}
    clients:
      - client_id: spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://app.acme.test/callback", "https://*.preview.acme.test/cb", "http://localhost:3000/", "https://app.acme.test/cb2?next=https://*.x", "com.example.app:/oauth2redirect"]
        web_origins: ["https://app.acme.test"]
        skip_non_verifiable_callback_uri_confirmation_prompt: true
      - client_id: other-spa
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["https://other.acme.test/cb"]
        web_origins: ["https://other.acme.test"]
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
      - client_id: partner
        app_type: regular_web
        client_secret: partner-secret
        is_first_party: false
        refresh_token: {rotation_type: rotating, expiration_type: expiring}
        grant_types: [authorization_code]
        callbacks: ["https://partner.example/cb", "http://localhost:4000/cb"]
      - client_id: partner-open
        app_type: regular_web
        client_secret: partner-open-secret
        is_first_party: false
        third_party_security_mode: permissive
        redirection_policy: allow_always
        grant_types: [authorization_code]
        callbacks: ["https://open.example/cb"]
      - client_id: par-web
        app_type: regular_web
        client_secret: par-web-secret
        grant_types: [authorization_code]
        callbacks: ["https://par.acme.test/cb", "https://par.acme.test/cb2"]
      - client_id: par-required
        app_type: regular_web
        client_secret: par-required-secret
        require_pushed_authorization_requests: true
        grant_types: [authorization_code]
        callbacks: ["https://req.acme.test/cb"]
      - client_id: local
        app_type: spa
        grant_types: [authorization_code]
        callbacks: ["http://localhost:5000/cb"]
      - client_id: tv
        app_type: native
        grant_types: ["urn:ietf:params:oauth:grant-type:device_code", refresh_token]
    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true, enabled_clients: [spa, web, local, par-web, par-required, tv]}
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
	if err := seed.Apply(context.Background(), st, f, fixedNow, nil); err != nil {
		t.Fatal(err)
	}
	tn, err := st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{st: st, tenant: tn}
}
