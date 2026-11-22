package seed

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"strings"
	"testing"
)

func TestSeedOIDCSettings(t *testing.T) {
	st := memory.New()
	defer st.Close()
	raw := fmt.Sprintf(`tenants:
 - name: acme
   clients:
    - client_id: web
      app_type: regular_web
      client_secret: %s
      jwt_configuration: {alg: HS256, lifetime_in_seconds: 600}
      oidc_support: {is_allowed: true, allowed_scopes: [email, phone]}
      oidc_logout:
       backchannel_logout_urls: [https://rp.example/logout]
       backchannel_logout_initiators: {mode: all}
       backchannel_logout_session_metadata: {include: true}
`, secrets.RandomString(40))
	f, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.Tenants().GetByName(t.Context(), "acme")
	c, err := st.Clients().Get(t.Context(), tenant.ID, "web")
	if err != nil {
		t.Fatal(err)
	}
	if c.IDTokenAlg != "HS256" || c.IDTokenLifetime != 600 || c.OIDCLogout == nil || c.OIDCLogout.InitiatorsMode != "all" || c.OIDCSupport == nil || len(c.OIDCSupport.AllowedScopes) != 2 {
		t.Fatal("OIDC seed settings lost")
	}
	if err := Apply(t.Context(), st, f, fixedNow, testWrapper(t)); err != nil {
		t.Fatal("reapply", err)
	}
	cleared, err := Parse([]byte(`tenants: [{name: acme, clients: [{client_id: web, app_type: regular_web, oidc_logout: null, oidc_support: null}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	cleared.Mode = ModeCreateOnly
	if err := Apply(t.Context(), st, cleared, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	c, _ = st.Clients().Get(t.Context(), tenant.ID, "web")
	if c.OIDCLogout == nil || c.IDTokenAlg != "HS256" {
		t.Fatal("create_only overwrote OIDC settings")
	}
	cleared.Mode = ModeApply
	if err := Apply(t.Context(), st, cleared, fixedNow, testWrapper(t)); err != nil {
		t.Fatal(err)
	}
	c, _ = st.Clients().Get(t.Context(), tenant.ID, "web")
	if c.OIDCLogout != nil || c.OIDCSupport != nil || c.IDTokenAlg != "RS256" {
		t.Fatal("OIDC settings did not clear")
	}

}

type noOIDCStore struct{ store.Store }

func (noOIDCStore) CheckOIDCLogoutSupport(context.Context) error {
	return store.ErrOIDCLogoutUnavailable
}
func TestSeedOIDCCapability(t *testing.T) {
	f, err := Parse([]byte(`tenants: [{name: acme, clients: [{client_id: spa, app_type: spa, oidc_logout: {backchannel_logout_urls: [https://rp.example/logout]}}]}]`))
	if err != nil {
		t.Fatal(err)
	}
	st := memory.New()
	defer st.Close()
	if err := Apply(t.Context(), noOIDCStore{st}, f, fixedNow, testWrapper(t)); !errors.Is(err, store.ErrOIDCLogoutUnavailable) {
		t.Fatal("unsupported seed accepted", err)
	}
	tenants, _ := st.Tenants().List(t.Context())
	if len(tenants) != 0 {
		t.Fatal("capability refusal applied partial seed")
	}
}
func TestSeedOIDCValidation(t *testing.T) {
	for _, fields := range []string{`app_type: spa, jwt_configuration: {alg: HS256}`, `app_type: regular_web, client_secret: ` + strings.Repeat("a", 31) + `, jwt_configuration: {alg: HS256}`, `app_type: spa, jwt_configuration: {alg: ES256}`, `app_type: spa, oidc_support: {is_allowed: true, allow_all_scopes: true, allowed_scopes: [email]}`, `app_type: spa, oidc_logout: {backchannel_logout_urls: [http://rp.example/logout]}`, `app_type: spa, oidc_logout: {unexpected: true}`} {
		if _, err := Parse([]byte(`tenants: [{name: acme, clients: [{client_id: client, ` + fields + `}]}]`)); err == nil {
			t.Fatal("invalid OIDC seed accepted")
		}
	}
}
