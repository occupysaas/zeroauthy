package oauth

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// A profile accidentally reusing the cached legacy signer, or selecting claims
// from the requested scopes rather than permissions, breaks these assertions.
func TestRBACTokenProfiles(t *testing.T) {
	ctx := context.Background()
	km := newTestKeys(t, "ten_a")
	m := &Minter{Keys: km, Now: fixedNow}
	var previousJTI string
	for _, dialect := range []string{"", "access_token", "access_token_authz", "rfc9068_profile", "rfc9068_profile_authz"} {
		for _, include := range []bool{false, true} {
			t.Run(dialect+"/permissions="+map[bool]string{false: "off", true: "on"}[include], func(t *testing.T) {
				p := AccessTokenParams{TenantID: "ten_a", Issuer: "https://a.example.test/", Subject: "auth0|1", Audience: []string{"https://api.test", "https://a.example.test/userinfo"}, ClientID: "client", Scopes: []string{"openid", "read:x"}, GrantType: "password", Lifetime: time.Hour, TokenDialect: dialect, Permissions: []string{"write:x", "read:x", "write:x"}, IncludePermissions: include}
				raw, err := m.AccessToken(ctx, p)
				if err != nil {
					t.Fatal(err)
				}
				claims, _ := verifyToken(t, km, "ten_a", raw)
				parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
				if err != nil {
					t.Fatal(err)
				}
				rfc := strings.HasPrefix(dialect, "rfc9068_")
				wantType := "JWT"
				if rfc {
					wantType = "at+jwt"
				}
				if got := parsed.Headers[0].ExtraHeaders[jose.HeaderType]; got != wantType {
					t.Fatalf("typ = %v, want %s", got, wantType)
				}
				if claims["iss"] != "https://a.example.test/" || claims["sub"] != "auth0|1" || claims["scope"] != "openid read:x" || claims["exp"].(float64)-claims["iat"].(float64) != 3600 {
					t.Fatalf("claims = %#v", claims)
				}
				if rfc {
					if claims["client_id"] != "client" || claims["azp"] != nil || claims["gty"] != nil {
						t.Fatalf("RFC claims = %#v", claims)
					}
				} else if claims["azp"] != "client" || claims["gty"] != "password" || claims["client_id"] != nil {
					t.Fatalf("legacy claims = %#v", claims)
				}
				wantPermissions := include && strings.HasSuffix(dialect, "_authz")
				if wantPermissions {
					if !reflect.DeepEqual(claims["permissions"], []any{"read:x", "write:x"}) {
						t.Fatalf("permissions = %#v", claims["permissions"])
					}
				} else if _, ok := claims["permissions"]; ok {
					t.Fatalf("unexpected permissions = %#v", claims["permissions"])
				}
				jti, _ := claims["jti"].(string)
				if jti == "" || jti == previousJTI {
					t.Fatalf("nonunique jti %q", jti)
				}
				previousJTI = jti
			})
		}
	}
	for _, dialect := range []string{"access_token_authz", "rfc9068_profile_authz"} {
		raw, err := m.AccessToken(ctx, AccessTokenParams{TenantID: "ten_a", Issuer: "https://a.example.test/", Subject: "auth0|1", ClientID: "client", Audience: []string{"https://api.test"}, TokenDialect: dialect, IncludePermissions: true})
		if err != nil {
			t.Fatal(err)
		}
		claims, _ := verifyToken(t, km, "ten_a", raw)
		b, _ := json.Marshal(claims["permissions"])
		if string(b) != "[]" {
			t.Fatalf("empty permissions = %s", b)
		}
	}
	if _, err := m.AccessToken(ctx, AccessTokenParams{TenantID: "ten_a", Audience: []string{"https://api.test"}, TokenDialect: "unknown"}); err == nil {
		t.Fatal("unknown dialect signed")
	}
	before, err := m.AccessToken(ctx, AccessTokenParams{TenantID: "ten_a", Issuer: "https://a/", Subject: "user", ClientID: "client", Audience: []string{"https://api.test"}, TokenDialect: "rfc9068_profile"})
	if err != nil {
		t.Fatal(err)
	}
	_, beforeKID := verifyToken(t, km, "ten_a", before)
	if err := km.Rotate(ctx, "ten_a"); err != nil {
		t.Fatal(err)
	}
	after, err := m.AccessToken(ctx, AccessTokenParams{TenantID: "ten_a", Issuer: "https://a/", Subject: "user", ClientID: "client", Audience: []string{"https://api.test"}, TokenDialect: "rfc9068_profile"})
	if err != nil {
		t.Fatal(err)
	}
	_, afterKID := verifyToken(t, km, "ten_a", after)
	if beforeKID == afterKID {
		t.Fatal("rotation did not select new key")
	}
	verifyToken(t, km, "ten_a", before)
	id, err := m.IDToken(ctx, IDTokenParams{TenantID: "ten_a", Issuer: "https://a/", ClientID: "client", User: &store.User{UserID: "auth0|1"}, Scopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	idClaims, _ := verifyToken(t, km, "ten_a", id)
	parsed, _ := jwt.ParseSigned(id, []jose.SignatureAlgorithm{jose.RS256})
	if parsed.Headers[0].ExtraHeaders[jose.HeaderType] != "JWT" || idClaims["permissions"] != nil || idClaims["client_id"] != nil {
		t.Fatalf("ID token changed: %#v", idClaims)
	}
}

func TestRBACTokenProfilesRFCRequiredClaims(t *testing.T) {
	m := &Minter{Keys: newTestKeys(t, "ten_a"), Now: fixedNow}
	for _, missing := range []string{"issuer", "subject", "client", "audience"} {
		t.Run(missing, func(t *testing.T) {
			p := AccessTokenParams{TenantID: "ten_a", Issuer: "https://a/", Subject: "user", ClientID: "client", Audience: []string{"https://api.test"}, TokenDialect: "rfc9068_profile"}
			switch missing {
			case "issuer":
				p.Issuer = ""
			case "subject":
				p.Subject = ""
			case "client":
				p.ClientID = ""
			case "audience":
				p.Audience = []string{""}
			}
			if _, err := m.AccessToken(context.Background(), p); err == nil {
				t.Fatal("RFC access token minted without " + missing)
			}
		})
	}
}
