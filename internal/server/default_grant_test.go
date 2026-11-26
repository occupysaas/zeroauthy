package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/testutil/contract"
)

const defaultGrantSeed = `
tenants:
  - name: tp
    domains: [tp.example.test]
    resource_servers: [{identifier: "https://api.tp.test", scopes: [{value: "read:things"}]}]
    clients:
      - {client_id: partner, app_type: non_interactive, is_first_party: false, client_secret: s3cret-s3cret-s3cret, grant_types: [client_credentials]}
      - {client_id: inhouse, app_type: non_interactive, client_secret: s3cret-s3cret-s3cret, grant_types: [client_credentials]}
`

// A default grant for third-party clients lets a third-party client
// without its own grant get tokens for the API, and never a first-party
// client (Plan 41b, LR41b-4).
func TestDefaultGrantThroughServer(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	f, err := seed.Parse([]byte(defaultGrantSeed))
	if err != nil {
		t.Fatal(err)
	}
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err := seed.Apply(ctx, st, f, nil, w); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), w)
	tn, _ := st.Tenants().GetByName(ctx, "tp")
	if err := km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	h := contract.Wrap(t, New(Deps{Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), "", false),
		Sessions: &session.Manager{Store: st}, Mailer: discardMailer{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}))
	token := func(clientID string) int {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {"s3cret-s3cret-s3cret"}, "audience": {"https://api.tp.test"}}
		r := httptest.NewRequest(http.MethodPost, "https://tp.example.test/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if c := token("partner"); c != http.StatusForbidden {
		t.Fatalf("no grant: %d", c)
	}
	def := &store.ClientGrant{TenantID: tn.ID, ID: "cgr_default000000001", Audience: "https://api.tp.test", SubjectType: store.SubjectTypeClient,
		Scopes: []string{"read:things"}, DefaultFor: store.GrantDefaultForThirdParty, OrganizationUsage: store.OrgUsageDeny, Origin: store.OriginAPI}
	if err := st.ClientGrants().Create(ctx, def); err != nil {
		t.Fatal(err)
	}
	if c := token("partner"); c != http.StatusOK {
		t.Fatalf("third party with the default grant: %d", c)
	}
	if c := token("inhouse"); c != http.StatusForbidden {
		t.Fatalf("first party must not use the default grant: %d", c)
	}
	if err := st.ClientGrants().Delete(ctx, tn.ID, def.ID); err != nil {
		t.Fatal(err)
	}
	if c := token("partner"); c != http.StatusForbidden {
		t.Fatalf("after deleting the default: %d", c)
	}
}
