package oauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
)

const signingTestSecret = "an-hs256-secret-of-over-32-bytes!"

// setAPISigning changes the seeded API the way the Management API does.
func (f *fixture) setAPISigning(t *testing.T, alg, secret string) {
	t.Helper()
	tid := f.tenantID(t, "acme")
	rs, err := f.st.ResourceServers().GetByIdentifier(t.Context(), tid, "https://api.acme.test")
	if err != nil {
		t.Fatal(err)
	}
	rs.SigningAlg = alg
	if secret != "" {
		if rs.SigningSecretSealed, err = keys.SealAPISigningSecret(f.wrapper, tid, rs.ID, secret); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
}

func hs256Claims(t *testing.T, raw, secret string) (map[string]any, jose.Header) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q", raw)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if parts[2] != base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("HS256 signature does not match the API secret")
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	return claims, tok.Headers[0]
}

func TestAPISigningHS256TokenEndpoint(t *testing.T) {
	f := newFixture(t)
	f.setAPISigning(t, "HS256", signingTestSecret)

	rec, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	if rec.Code != 200 {
		t.Fatalf("client credentials = %d %v", rec.Code, body)
	}
	claims, h := hs256Claims(t, body["access_token"].(string), signingTestSecret)
	if h.KeyID != "" || claims["aud"] != "https://api.acme.test" {
		t.Errorf("client credentials: header %+v claims %v", h, claims)
	}

	// A user token with openid carries no userinfo audience (LR35-9); the ID
	// token stays RS256.
	code, body := f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://api.acme.test", "scope", "openid"))
	if code != 200 {
		t.Fatalf("password = %d %v", code, body)
	}
	claims, _ = hs256Claims(t, body["access_token"].(string), signingTestSecret)
	if claims["aud"] != "https://api.acme.test" {
		t.Errorf("aud = %v, want only the API", claims["aud"])
	}
	verifyToken(t, f.keys, f.tenantID(t, "acme"), body["id_token"].(string))
}

func TestAPISigningPS256TokenEndpoint(t *testing.T) {
	f := newFixture(t)
	f.setAPISigning(t, "PS256", "")
	tid := f.tenantID(t, "acme")
	check := func(raw string) jwt.Audience {
		t.Helper()
		tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.PS256})
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Aud jwt.Audience `json:"aud"`
		}
		if err := f.keys.Verify(t.Context(), tid, raw, &c); err != nil {
			t.Fatalf("not verifiable with the tenant keys: %v (%v)", err, tok.Headers)
		}
		return c.Aud
	}
	_, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	check(body["access_token"].(string))
	_, body = f.pwCall2(t, "openid")
	if aud := check(body["access_token"].(string)); len(aud) != 2 {
		t.Errorf("aud = %v, want the userinfo audience kept (C18)", aud)
	}
}

func (f *fixture) pwCall2(t *testing.T, scope string) (int, map[string]any) {
	t.Helper()
	return f.pwCall(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", "https://api.acme.test", "scope", scope))
}

func TestAPISigningHS256WithoutSecretFails(t *testing.T) {
	f := newFixture(t)
	f.setAPISigning(t, "HS256", "")
	rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	if rec.Code != 500 || body["error"] != "server_error" {
		t.Fatalf("= %d %v, want server_error rather than a token signed another way", rec.Code, body)
	}
}

func TestAPISigningDefaultsToRS256(t *testing.T) {
	f := newFixture(t)
	_, body := f.call(t, true, tokenCall{host: "acme.example.test", form: cc("m2m", "m2m-secret", "audience", "https://api.acme.test")})
	verifyToken(t, f.keys, f.tenantID(t, "acme"), body["access_token"].(string))
}
