package clientcred

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

const (
	clientID = "client_abc"
	issuer   = "https://t.example.test/"
)

func readTD(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func privKey(t *testing.T, name string) *rsa.PrivateKey {
	t.Helper()
	blk, _ := pem.Decode([]byte(readTD(t, name)))
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}

func cred(t *testing.T, id, spki, alg string) *store.ClientCredential {
	t.Helper()
	p, err := ParsePEM("public_key", readTD(t, spki), alg)
	if err != nil {
		t.Fatal(err)
	}
	return &store.ClientCredential{TenantID: "t", ClientID: clientID, ID: id, Type: "public_key",
		KID: p.KID, Alg: alg, PublicKeyDER: p.DER, Thumbprint: p.Thumbprint}
}

func sign(t *testing.T, key any, alg jose.SignatureAlgorithm, hdr map[string]any, claims any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	for k, v := range hdr {
		opts.WithHeader(jose.HeaderKey(k), v)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Sign(pl)
	if err != nil {
		t.Fatal(err)
	}
	c, err := o.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func goodClaims() map[string]any {
	return map[string]any{"iss": clientID, "sub": clientID, "aud": issuer, "jti": "jti-1",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix()}
}

func with(m map[string]any, kv ...any) map[string]any {
	c := map[string]any{}
	for k, v := range m {
		c[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == nil {
			delete(c, kv[i].(string))
		} else {
			c[kv[i].(string)] = kv[i+1]
		}
	}
	return c
}

func TestParsePEMForms(t *testing.T) {
	spki, err := ParsePEM("public_key", readTD(t, "rsa2048.spki.pem"), "RS256")
	if err != nil {
		t.Fatal(err)
	}
	pk1, err := ParsePEM("public_key", readTD(t, "rsa2048.pkcs1.pem"), "RS384")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := ParsePEM("x509_cert", readTD(t, "rsa2048.cert.pem"), "PS256")
	if err != nil {
		t.Fatal(err)
	}
	k := privKey(t, "rsa2048.priv.pem")
	tp, _ := (&jose.JSONWebKey{Key: &k.PublicKey}).Thumbprint(crypto.SHA256)
	want := base64.RawURLEncoding.EncodeToString(tp)
	for name, p := range map[string]*Parsed{"spki": spki, "pkcs1": pk1, "cert": crt} {
		if p.KID != want || p.Thumbprint != want {
			t.Errorf("%s: kid=%q thumbprint=%q want %q", name, p.KID, p.Thumbprint, want)
		}
		if _, err := x509.ParsePKIXPublicKey(p.DER); err != nil {
			t.Errorf("%s: DER is not SPKI: %v", name, err)
		}
	}
	if spki.CertNotAfter != nil || pk1.CertNotAfter != nil {
		t.Error("keys must not set CertNotAfter")
	}
	if crt.CertNotAfter == nil || !crt.CertNotAfter.Equal(time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("CertNotAfter = %v", crt.CertNotAfter)
	}
	exp, err := ParsePEM("x509_cert", readTD(t, "rsa2048.expired.cert.pem"), "")
	if err != nil || exp.CertNotAfter == nil || !exp.CertNotAfter.Before(now) {
		t.Errorf("expired cert should parse with past CertNotAfter: %v %v", exp, err)
	}
	if _, err := ParsePEM("public_key", readTD(t, "rsa4096.spki.pem"), "RS256"); err != nil {
		t.Errorf("4096-bit refused: %v", err)
	}
}

func TestParsePEMRefuses(t *testing.T) {
	good := readTD(t, "rsa2048.spki.pem")
	cases := []struct{ name, typ, pem, alg string }{
		{"rsa1024", "public_key", readTD(t, "rsa1024.spki.pem"), "RS256"},
		{"rsa8192", "public_key", readTD(t, "rsa8192.spki.pem"), "RS256"},
		{"ec", "public_key", readTD(t, "ec256.spki.pem"), "RS256"},
		{"garbage", "public_key", "not a pem", "RS256"},
		{"two blocks", "public_key", good + good, "RS256"},
		{"HS256", "public_key", good, "HS256"},
		{"ES256", "public_key", good, "ES256"},
		{"type mismatch", "x509_cert", good, "RS256"},
		{"cert as key", "public_key", readTD(t, "rsa2048.cert.pem"), "RS256"},
		{"unknown type", "other", good, "RS256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParsePEM(c.typ, c.pem, c.alg)
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %v", err)
			}
		})
	}
}

func TestVerifyAssertion(t *testing.T) {
	k := privKey(t, "rsa2048.priv.pem")
	hmacTok := func() string {
		return sign(t, []byte(readTD(t, "rsa2048.spki.pem")), jose.HS256, nil, goodClaims())
	}
	noneTok := func() string {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
		p, _ := json.Marshal(goodClaims())
		return h + "." + base64.RawURLEncoding.EncodeToString(p) + "."
	}
	rs := func(alg jose.SignatureAlgorithm, c map[string]any) string { return sign(t, k, alg, nil, c) }
	expiredAt := now.Add(-time.Second)
	cases := []struct {
		name  string
		alg   string
		raw   func() string
		creds func() []*store.ClientCredential
		ok    bool
	}{
		{name: "RS256", alg: "RS256", raw: func() string { return rs(jose.RS256, goodClaims()) }, ok: true},
		{name: "RS384", alg: "RS384", raw: func() string { return rs(jose.RS384, goodClaims()) }, ok: true},
		{name: "PS256", alg: "PS256", raw: func() string { return rs(jose.PS256, goodClaims()) }, ok: true},
		{name: "typ JWT", alg: "RS256", raw: func() string { return sign(t, k, jose.RS256, map[string]any{"typ": "JWT"}, goodClaims()) }, ok: true},
		{name: "typ jwt", alg: "RS256", raw: func() string { return sign(t, k, jose.RS256, map[string]any{"typ": "jwt"}, goodClaims()) }, ok: true},
		// A request object must not double as a client assertion when one key
		// serves both settings.
		{name: "request object typ", alg: "RS256", raw: func() string {
			return sign(t, k, jose.RS256, map[string]any{"typ": "oauth-authz-req+jwt"}, goodClaims())
		}},
		{name: "aud array", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "aud", []string{"x", issuer}))
		}, ok: true},
		{name: "endpoint aud", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "aud", issuer+"oauth/token"))
		}, ok: true},
		{name: "exp-iat 300 ok", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "exp", now.Add(300*time.Second).Unix()))
		}, ok: true},
		{name: "alg mismatch", alg: "RS384", raw: func() string { return rs(jose.RS256, goodClaims()) }},
		{name: "alg none", alg: "RS256", raw: noneTok},
		{name: "hs256 with pem secret", alg: "RS256", raw: hmacTok},
		{name: "iss != sub", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "sub", "other")) }},
		{name: "iss wrong client", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "iss", "other", "sub", "other"))
		}},
		{name: "aud mismatch", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "aud", "https://evil/")) }},
		{name: "missing aud", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "aud", nil)) }},
		{name: "missing exp", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "exp", nil)) }},
		{name: "exp non-number", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "exp", "soon")) }},
		{name: "expired", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "iat", nil, "exp", now.Add(-11*time.Second).Unix()))
		}},
		{name: "exp-iat 301", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "exp", now.Add(301*time.Second).Unix()))
		}},
		{name: "no iat, exp too far", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "iat", nil, "exp", now.Add(301*time.Second).Unix()))
		}},
		{name: "nbf +11", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "nbf", now.Add(11*time.Second).Unix()))
		}},
		{name: "nbf +10 ok", alg: "RS256", ok: true, raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "nbf", now.Add(10*time.Second).Unix()))
		}},
		{name: "missing jti", alg: "RS256", raw: func() string { return rs(jose.RS256, with(goodClaims(), "jti", nil)) }},
		{name: "jti 65", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "jti", strings.Repeat("j", 65)))
		}},
		{name: "jti 64 ok", alg: "RS256", ok: true, raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "jti", strings.Repeat("j", 64)))
		}},
		{name: "iss 65", alg: "RS256", raw: func() string {
			l := strings.Repeat("c", 65)
			return rs(jose.RS256, with(goodClaims(), "iss", l, "sub", l))
		}},
		{name: "raw 2049", alg: "RS256", raw: func() string { return strings.Repeat("a", 2049) }},
		{name: "oversized valid token", alg: "RS256", raw: func() string {
			return rs(jose.RS256, with(goodClaims(), "pad", strings.Repeat("p", 2100)))
		}},
		{name: "garbage", alg: "RS256", raw: func() string { return "a.b.c" }},
		{name: "empty", alg: "RS256", raw: func() string { return "" }},
		{name: "crit header", alg: "RS256", raw: func() string {
			return sign(t, k, jose.RS256, map[string]any{"crit": []string{"x"}, "x": 1}, goodClaims())
		}},
		{name: "wrong key", alg: "RS256", raw: func() string { return sign(t, privKey(t, "rsa2048b.priv.pem"), jose.RS256, nil, goodClaims()) }},
		{name: "expired credential", alg: "RS256", raw: func() string { return rs(jose.RS256, goodClaims()) },
			creds: func() []*store.ClientCredential {
				c := cred(t, "c1", "rsa2048.spki.pem", "RS256")
				c.ExpiresAt = &expiredAt
				return []*store.ClientCredential{c}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			creds := []*store.ClientCredential{cred(t, "c1", "rsa2048.spki.pem", c.alg)}
			if c.creds != nil {
				creds = c.creds()
			}
			claims, err := Verify(VerifyInput{Raw: c.raw(), ClientID: clientID, Audiences: []string{issuer, issuer + "oauth/token"},
				Purpose: Assertion, Credentials: creds, Now: now,
				UseJTI: func(string, time.Time) error { return nil }})
			if c.ok {
				if err != nil || claims["iss"] != clientID {
					t.Fatalf("want ok, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) || claims != nil {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
		})
	}
}

func TestVerifyKidSelection(t *testing.T) {
	a, b := cred(t, "ca", "rsa2048.spki.pem", "RS256"), cred(t, "cb", "rsa2048b.spki.pem", "RS256")
	ka, kb := privKey(t, "rsa2048.priv.pem"), privKey(t, "rsa2048b.priv.pem")
	in := func(raw string, creds ...*store.ClientCredential) VerifyInput {
		return VerifyInput{Raw: raw, ClientID: clientID, Audiences: []string{issuer}, Purpose: Assertion,
			Credentials: creds, Now: now, UseJTI: func(string, time.Time) error { return nil }}
	}
	// kid selects only that credential.
	if _, err := Verify(in(sign(t, kb, jose.RS256, map[string]any{"kid": a.KID}, goodClaims()), a, b)); !errors.Is(err, ErrInvalid) {
		t.Errorf("kid=a signed by b must fail, got %v", err)
	}
	if _, err := Verify(in(sign(t, kb, jose.RS256, map[string]any{"kid": b.KID}, goodClaims()), a, b)); err != nil {
		t.Errorf("kid=b signed by b: %v", err)
	}
	if _, err := Verify(in(sign(t, ka, jose.RS256, map[string]any{"kid": "unknown-kid-123"}, goodClaims()), a, b)); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown kid must fail, got %v", err)
	}
	// without kid either verifies.
	for _, k := range []*rsa.PrivateKey{ka, kb} {
		if _, err := Verify(in(sign(t, k, jose.RS256, nil, goodClaims()), a, b)); err != nil {
			t.Errorf("no kid: %v", err)
		}
	}
	if _, err := Verify(in(sign(t, ka, jose.RS256, nil, goodClaims()))); !errors.Is(err, ErrInvalid) {
		t.Errorf("no credentials must fail, got %v", err)
	}
}

func TestVerifyReplay(t *testing.T) {
	c := cred(t, "c1", "rsa2048.spki.pem", "RS256")
	raw := sign(t, privKey(t, "rsa2048.priv.pem"), jose.RS256, nil, goodClaims())
	seen := map[string]bool{}
	var gotExp time.Time
	use := func(jti string, exp time.Time) error {
		if seen[jti] {
			return store.ErrConflict
		}
		seen[jti] = true
		gotExp = exp
		return nil
	}
	in := VerifyInput{Raw: raw, ClientID: clientID, Audiences: []string{issuer}, Purpose: Assertion,
		Credentials: []*store.ClientCredential{c}, Now: now, UseJTI: use}
	if _, err := Verify(in); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(2*time.Minute + 10*time.Second); !gotExp.Equal(want) {
		t.Errorf("jti recorded until %v, want exp+leeway %v", gotExp, want)
	}
	if _, err := Verify(in); !errors.Is(err, ErrInvalid) {
		t.Errorf("replay: %v", err)
	}
	in.UseJTI = func(string, time.Time) error { return errors.New("db down") }
	in.Raw = sign(t, privKey(t, "rsa2048.priv.pem"), jose.RS256, nil, with(goodClaims(), "jti", "fresh"))
	if _, err := Verify(in); !errors.Is(err, ErrInvalid) {
		t.Errorf("store failure must fail closed: %v", err)
	}
	in.UseJTI = nil
	if _, err := Verify(in); !errors.Is(err, ErrInvalid) {
		t.Errorf("nil UseJTI must fail closed: %v", err)
	}
	// A bad signature never reaches UseJTI.
	called := false
	in.UseJTI = func(string, time.Time) error { called = true; return nil }
	in.Raw = sign(t, privKey(t, "rsa2048b.priv.pem"), jose.RS256, nil, goodClaims())
	if _, err := Verify(in); err == nil || called {
		t.Errorf("UseJTI called before signature check: called=%v err=%v", called, err)
	}
}

func TestVerifyRequestObject(t *testing.T) {
	c := cred(t, "c1", "rsa2048.spki.pem", "RS256")
	k := privKey(t, "rsa2048.priv.pem")
	jarClaims := func(kv ...any) map[string]any {
		return with(map[string]any{"iss": clientID, "aud": issuer, "exp": now.Add(10 * time.Minute).Unix(),
			"client_id": clientID, "redirect_uri": "https://app/cb"}, kv...)
	}
	var used []string
	run := func(hdr map[string]any, claims map[string]any) (map[string]any, error) {
		return Verify(VerifyInput{Raw: sign(t, k, jose.RS256, hdr, claims), ClientID: clientID, Audiences: []string{issuer},
			Purpose: RequestObject, Credentials: []*store.ClientCredential{c}, Now: now,
			UseJTI: func(j string, _ time.Time) error { used = append(used, j); return nil }})
	}
	for _, typ := range []any{nil, "JWT", "jwt", "oauth-authz-req+jwt"} {
		h := map[string]any{}
		if typ != nil {
			h["typ"] = typ
		}
		cl, err := run(h, jarClaims())
		if err != nil || cl["redirect_uri"] != "https://app/cb" {
			t.Errorf("typ %v: %v", typ, err)
		}
	}
	if len(used) != 0 {
		t.Errorf("no jti => UseJTI must not run, got %v", used)
	}
	if _, err := run(map[string]any{"typ": "at+jwt"}, jarClaims()); !errors.Is(err, ErrInvalid) {
		t.Errorf("at+jwt: %v", err)
	}
	if _, err := run(nil, jarClaims("jti", "r1")); err != nil || len(used) != 1 || used[0] != "r1" {
		t.Errorf("jti must go through UseJTI: %v %v", err, used)
	}
	if _, err := run(nil, jarClaims("jti", strings.Repeat("j", 65))); !errors.Is(err, ErrInvalid) {
		t.Errorf("long jti: %v", err)
	}
	if _, err := run(nil, jarClaims("exp", nil)); !errors.Is(err, ErrInvalid) {
		t.Errorf("exp required: %v", err)
	}
	if _, err := run(nil, jarClaims("exp", now.Add(3600*time.Second).Unix())); err != nil {
		t.Errorf("3600 s lifetime: %v", err)
	}
	if _, err := run(nil, jarClaims("exp", now.Add(3601*time.Second).Unix())); !errors.Is(err, ErrInvalid) {
		t.Errorf("3601 s lifetime: %v", err)
	}
	if _, err := run(nil, jarClaims("iss", "other")); !errors.Is(err, ErrInvalid) {
		t.Errorf("iss: %v", err)
	}
	if _, err := run(nil, jarClaims("aud", "https://evil/")); !errors.Is(err, ErrInvalid) {
		t.Errorf("aud: %v", err)
	}
	// A request object is not capped at 2048 bytes.
	if _, err := run(nil, jarClaims("claims", strings.Repeat("p", 4000))); err != nil {
		t.Errorf("large request object: %v", err)
	}
}

func TestVerifyErrorOmitsToken(t *testing.T) {
	c := cred(t, "c1", "rsa2048.spki.pem", "RS256")
	raws := []string{
		sign(t, privKey(t, "rsa2048b.priv.pem"), jose.RS256, nil, goodClaims()),
		sign(t, privKey(t, "rsa2048.priv.pem"), jose.RS256, nil, with(goodClaims(), "aud", "https://evil/")),
		sign(t, privKey(t, "rsa2048.priv.pem"), jose.RS256, nil, with(goodClaims(), "jti", strings.Repeat("j", 65))),
	}
	for _, raw := range raws {
		_, err := Verify(VerifyInput{Raw: raw, ClientID: clientID, Audiences: []string{issuer}, Purpose: Assertion,
			Credentials: []*store.ClientCredential{c}, Now: now, UseJTI: func(string, time.Time) error { return nil }})
		if err == nil {
			t.Fatal("want error")
		}
		for _, part := range strings.Split(raw, ".") {
			if strings.Contains(err.Error(), part) {
				t.Errorf("error leaks token segment: %v", err)
			}
		}
		if strings.Contains(err.Error(), "evil") {
			t.Errorf("error leaks claim value: %v", err)
		}
	}
}

// TestVerifyRefusesJSONSerialization pins compact-only parsing: the same
// signed token in JWS JSON serialization is refused.
func TestVerifyRefusesJSONSerialization(t *testing.T) {
	k := privKey(t, "rsa2048.priv.pem")
	c := cred(t, "c1", "rsa2048.spki.pem", "RS256")
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := json.Marshal(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	o, err := s.Sign(pl)
	if err != nil {
		t.Fatal(err)
	}
	in := VerifyInput{ClientID: clientID, Audiences: []string{issuer}, Purpose: Assertion,
		Credentials: []*store.ClientCredential{c}, Now: now, UseJTI: func(string, time.Time) error { return nil }}
	in.Raw = o.FullSerialize()
	if _, err := Verify(in); !errors.Is(err, ErrInvalid) {
		t.Errorf("JSON serialization: err = %v, want ErrInvalid", err)
	}
	compact, err := o.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	in.Raw = compact
	if _, err := Verify(in); err != nil {
		t.Fatalf("compact form: %v", err)
	}
}
