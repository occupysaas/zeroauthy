package logout

import (
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func tokenService(t *testing.T) *Service {
	st := memory.New()
	t.Cleanup(func() { _ = st.Close() })
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	km := keys.NewManager(st.SigningKeys(), wrapper)
	if err := km.Ensure(t.Context(), "tenant"); err != nil {
		t.Fatal(err)
	}
	return &Service{Store: st, Keys: km, Now: func() time.Time { return time.Unix(1800000000, 0).UTC() }}
}
func TestLogoutTokenShape(t *testing.T) {
	service := tokenService(t)
	client := &store.Client{TenantID: "tenant", ClientID: "rp", IDTokenAlg: "HS256"}
	session := &store.LoginSession{TenantID: "tenant", ID: "session", UserID: "oidc|subject", ClientIDs: []string{"rp"}}
	for _, compat := range []bool{false, true} {
		service.Compat.LogoutTokenTypJWT = compat
		raw, err := service.token(t.Context(), "tenant", "https://tenant.example/", client, session)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		if err != nil {
			t.Fatal(err)
		}
		wantType := "logout+jwt"
		if compat {
			wantType = "JWT"
		}
		if parsed.Headers[0].ExtraHeaders[jose.HeaderType] != wantType {
			t.Fatal("wrong logout token type")
		}
		set, err := service.Keys.JWKS(t.Context(), "tenant")
		if err != nil {
			t.Fatal(err)
		}
		matching := set.Key(parsed.Headers[0].KeyID)
		if len(matching) != 1 {
			t.Fatal("missing tenant signing key")
		}
		var claims map[string]any
		if err := parsed.Claims(matching[0].Key, &claims); err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]any{"iss": "https://tenant.example/", "aud": "rp", "sub": "oidc|subject", "sid": "session", "iat": float64(1800000000), "exp": float64(1800000120)} {
			if claims[name] != want {
				t.Errorf("claim %s=%v want=%v", name, claims[name], want)
			}
		}
		events, ok := claims["events"].(map[string]any)
		if !ok {
			t.Fatal("events absent")
		}
		event, ok := events["http://schemas.openid.net/event/backchannel-logout"].(map[string]any)
		if !ok || len(event) != 0 {
			t.Fatal("logout event malformed")
		}
		if claims["jti"] == nil || claims["jti"] == "" || claims["nonce"] != nil || claims["session_metadata"] != nil {
			t.Fatal("logout token has missing identity or unexpected claims")
		}
		another, err := service.token(t.Context(), "tenant", "https://tenant.example/", client, session)
		if err != nil {
			t.Fatal(err)
		}
		if raw == another {
			t.Fatal("delivery retries reused a logout token identifier")
		}
	}
}
func TestLogoutTokenTenantBoundary(t *testing.T) {
	service := tokenService(t)
	client := &store.Client{TenantID: "tenant", ClientID: "rp"}
	session := &store.LoginSession{TenantID: "tenant", ID: "session", UserID: "u", ClientIDs: []string{"another-rp"}}
	if _, err := service.token(t.Context(), "tenant", "https://tenant.example/", client, session); err == nil {
		t.Fatal("nonparticipant received a token")
	}
	session.ClientIDs = []string{"rp"}
	session.TenantID = "other"
	if _, err := service.token(t.Context(), "tenant", "https://tenant.example/", client, session); err == nil {
		t.Fatal("cross-tenant session accepted")
	}
}
func TestLogoutTokenSessionMetadata(t *testing.T) {
	service := tokenService(t)
	include := true
	client := &store.Client{TenantID: "tenant", ClientID: "rp", OIDCLogout: &store.OIDCLogout{IncludeSessionMetadata: &include}}
	session := &store.LoginSession{TenantID: "tenant", ID: "session", UserID: "u", ClientIDs: []string{"rp"}}
	raw, err := service.token(t.Context(), "tenant", "https://tenant.example/", client, session)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	var claims map[string]any
	if parsed.UnsafeClaimsWithoutVerification(&claims) != nil {
		t.Fatal("invalid fixture token")
	}
	encoded, _ := json.Marshal(claims["session_metadata"])
	if string(encoded) != "{}" {
		t.Fatalf("empty metadata=%s", encoded)
	}
	session.Metadata = map[string]string{"organization": "test"}
	raw, err = service.token(t.Context(), "tenant", "https://tenant.example/", client, session)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ = jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	_ = parsed.UnsafeClaimsWithoutVerification(&claims)
	if claims["session_metadata"].(map[string]any)["organization"] != "test" {
		t.Fatal("session metadata missing")
	}
}
