package server

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
)

// TestMgmtDescriptorSocialConnections covers a Plan 39b descriptor strategy through the
// Management API: sealed secret, effective scope on read, immutable client_id,
// revision bumps.
func TestMgmtDescriptorSocialConnections(t *testing.T) {
	e := newConnEnv(t)
	const secret = "social-throwaway-secret-value"
	options := func(secret any, extra map[string]any) map[string]any {
		o := map[string]any{"client_id": "amzn1.application-oa2-client.example", "postal_code": true}
		if secret != nil {
			o["client_secret"] = secret
		}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	rec, out := e.do("POST", connBase, map[string]any{"name": "amazon", "strategy": "amazon", "options": options(secret, nil)})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "client_secret") {
		t.Fatal("response exposes client_secret")
	}
	scope, _ := out["options"].(map[string]any)["scope"].([]any)
	if len(scope) != 2 || scope[0] != "profile" || scope[1] != "postal_code" {
		t.Fatalf("effective scope not returned: %v", out["options"])
	}
	id := out["id"].(string)
	for _, c := range []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"name": "amazon-ca", "strategy": "amazon", "connected_accounts": map[string]any{"active": true}, "options": options(secret, nil)}, 400},
		{map[string]any{"name": "amazon-url", "strategy": "amazon", "options": options(secret, map[string]any{"tokenURL": "https://evil.example/token"})}, 400},
		{map[string]any{"name": "amazon-nosecret", "strategy": "amazon", "options": options(nil, nil)}, 400},
		{map[string]any{"name": "amazon-scope", "strategy": "amazon", "options": options(secret, map[string]any{"scope": []any{"profile"}})}, 400},
	} {
		if rec, _ := e.do("POST", connBase, c.body); rec.Code != c.want {
			t.Fatalf("%v: %d %s", c.body["name"], rec.Code, rec.Body)
		}
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(e.stored(id)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsSocial || cfg.AuthorizationURL != "https://www.amazon.com/ap/oa" || cfg.TokenURL != "https://api.amazon.com/auth/o2/token" || len(cfg.Scopes) != 2 {
		t.Fatalf("runtime configuration: %+v", cfg)
	}
	if e.stored(id).FederationRevision != 1 {
		t.Fatalf("revision=%d", e.stored(id).FederationRevision)
	}
	patch := func(o map[string]any, want int) {
		t.Helper()
		rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o})
		if rec.Code != want {
			t.Fatalf("PATCH: %d %s", rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatal("response exposes client_secret")
		}
	}
	patch(options(nil, nil), 200)
	if e.stored(id).FederationRevision != 1 {
		t.Fatalf("unchanged PATCH bumped revision to %d", e.stored(id).FederationRevision)
	}
	patch(options(nil, map[string]any{"postal_code": false}), 200)
	if e.stored(id).FederationRevision != 2 {
		t.Fatalf("scope change revision=%d", e.stored(id).FederationRevision)
	}
	changed := options(nil, nil)
	changed["client_id"] = "changed"
	patch(changed, 400)
	patch(options("", nil), 400)
}
