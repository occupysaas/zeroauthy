package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/resourceview"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func appleConnectionKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func TestAppleConnectionCredentials(t *testing.T) {
	e := newConnEnv(t)
	key, rotated := appleConnectionKey(t), appleConnectionKey(t)
	options := func(secret any) map[string]any {
		o := map[string]any{"client_id": "com.example.web", "team_id": "ABCDEFGHIJ", "kid": "0123456789", "scope": "name email", "non_persistent_attrs": []any{"picture"}}
		if secret != nil {
			o["app_secret"] = secret
		}
		return o
	}
	rec, out := e.do("POST", connBase, map[string]any{"name": "apple", "strategy": "apple", "options": options(key)})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	id := out["id"].(string)
	assertPublic := func(body string) {
		t.Helper()
		if strings.Contains(body, "app_secret") || strings.Contains(body, "PRIVATE KEY") {
			t.Fatal("public projection exposes Apple signing key")
		}
	}
	assertPublic(rec.Body.String())
	assertSecret := func(c *store.Connection, want string, revision int64) {
		t.Helper()
		if c.FederationRevision != revision {
			t.Fatalf("revision=%d want=%d", c.FederationRevision, revision)
		}
		if strings.Contains(toJSON(c.Extra), "PRIVATE KEY") || c.Extra["app_secret"] != nil || c.Extra["client_secret"] != nil {
			t.Fatal("plaintext secret stored")
		}
		creds, err := federation.OpenCredentials(e.w, e.tenant.ID, id, c.FederationSecretsSealed)
		if err != nil || creds.ClientSecret != want {
			t.Fatalf("sealed credentials mismatch: %v", err)
		}
	}
	assertSecret(e.stored(id), key, 1)
	cfg, err := federation.ParseConfig(*connrules.FromConnection(e.stored(id)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppleTeamID != "ABCDEFGHIJ" || cfg.AppleKID != "0123456789" || cfg.Issuer != "https://appleid.apple.com" || !cfg.IsSocial || cfg.AuthorizationURL != "https://appleid.apple.com/auth/authorize" || cfg.TokenURL != "https://appleid.apple.com/auth/token" {
		t.Fatal("Apple runtime configuration lost signing identifiers, endpoints, issuer or social status")
	}
	if strings.Contains(toJSON(cfg), "PRIVATE KEY") {
		t.Fatal("runtime configuration holds plaintext signing key")
	}
	for _, target := range []string{connBase + "/" + id, connBase, connBase + "?fields=options&include_fields=true"} {
		rec, _ := e.do("GET", target, nil)
		if rec.Code != 200 {
			t.Fatalf("GET %s: %d", target, rec.Code)
		}
		assertPublic(rec.Body.String())
	}
	prior := e.stored(id)
	patch := func(o map[string]any, want int) {
		t.Helper()
		rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o})
		if rec.Code != want {
			t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
		}
		if want == 200 {
			assertPublic(rec.Body.String())
		}
	}
	patch(options(nil), 200)
	assertSecret(e.stored(id), key, 1)
	patch(options(key), 200)
	assertSecret(e.stored(id), key, 1)
	if !bytes.Equal(prior.FederationSecretsSealed, e.stored(id).FederationSecretsSealed) {
		t.Fatal("unchanged write resealed key")
	}
	patch(options(rotated), 200)
	assertSecret(e.stored(id), rotated, 2)
	o := options(nil)
	o["team_id"] = "ZYXWVUTSRQ"
	patch(o, 200)
	assertSecret(e.stored(id), rotated, 3)
	o["kid"] = "ABCDEFGHIJ"
	patch(o, 200)
	assertSecret(e.stored(id), rotated, 4)
	patch(o, 200)
	assertSecret(e.stored(id), rotated, 4)
	o["client_id"] = "com.example.changed"
	patch(o, 400)
	assertSecret(e.stored(id), rotated, 4)
	for _, bad := range []any{"", nil, "not a PEM"} {
		o := options(nil)
		o["app_secret"] = bad
		patch(o, 400)
		assertSecret(e.stored(id), rotated, 4)
	}
	// Even a legacy/bypassed plaintext Extra must not escape FromConnection,
	// event/resource projection, or a projection of the incoming write spec.
	legacy := *e.stored(id)
	legacy.Extra = map[string]any{"client_id": "com.example.web", "app_secret": key, "client_secret": "sentinel"}
	spec := connrules.FromConnection(&legacy)
	if spec.Options.Extra["app_secret"] != nil || spec.Options.Extra["client_secret"] != nil {
		t.Fatal("FromConnection retains plaintext provider key")
	}
	spec.Options.Extra["app_secret"] = key
	view, err := resourceview.Connection(spec, id, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(toJSON(view), "app_secret") || strings.Contains(toJSON(view), "PRIVATE KEY") {
		t.Fatal("resource view exposes write-only key")
	}
}
