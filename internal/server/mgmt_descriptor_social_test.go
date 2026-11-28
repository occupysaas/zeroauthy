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

func TestMgmtOAuth1Connections(t *testing.T) {
	e := newConnEnv(t)
	const secret = "oauth1-throwaway-consumer-secret"
	opts := func(extra map[string]any) map[string]any {
		o := map[string]any{"client_id": "consumer-key", "client_secret": secret,
			"requestTokenURL": "https://provider.example/oauth/request_token", "accessTokenURL": "https://provider.example/oauth/access_token",
			"userAuthorizationURL": "https://provider.example/oauth/authorize",
			"scripts":              map[string]any{"fetchUserProfile": "function fetchUserProfile(t, s, c, cb) { cb(null, {user_id: 'x'}); }"}}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	rec, out := e.do("POST", connBase, map[string]any{"name": "provider-o1", "strategy": "oauth1", "options": opts(nil)})
	if rec.Code != 201 || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(e.stored(out["id"].(string))))
	if err != nil || cfg.OAuth1 == nil || cfg.OAuth1.SignatureMethod != "HMAC-SHA1" || !cfg.IsSocial {
		t.Fatalf("runtime configuration: %+v %v", cfg, err)
	}
	for name, extra := range map[string]map[string]any{
		"plaintext": {"signatureMethod": "PLAINTEXT"},
		"no script": {"scripts": nil},
		"http":      {"accessTokenURL": "http://provider.example/oauth/access_token"},
	} {
		o := opts(extra)
		for k, v := range o {
			if v == nil {
				delete(o, k)
			}
		}
		if rec, _ := e.do("POST", connBase, map[string]any{"name": "o1-" + strings.ReplaceAll(name, " ", "-"), "strategy": "oauth1", "options": o}); rec.Code != 400 {
			t.Fatalf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// TestMgmtTier2Scope: a free-scope strategy returns scope as stored, and
// Exact and Evernote, which have none, return no scope (LR39d-1).
func TestMgmtTier2Scope(t *testing.T) {
	e := newConnEnv(t)
	secret := map[string]any{"client_id": "cid", "client_secret": "tier2-throwaway-secret"}
	with := func(extra map[string]any) map[string]any {
		o := map[string]any{}
		for k, v := range secret {
			o[k] = v
		}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	rec, out := e.do("POST", connBase, map[string]any{"name": "wp", "strategy": "wordpress", "options": with(map[string]any{"scope": "global"})})
	if rec.Code != 201 || out["options"].(map[string]any)["scope"] != "global" {
		t.Fatalf("wordpress: %d %v", rec.Code, out["options"])
	}
	rec, out = e.do("POST", connBase, map[string]any{"name": "wp2", "strategy": "wordpress", "options": with(nil)})
	if _, has := out["options"].(map[string]any)["scope"]; rec.Code != 201 || has {
		t.Fatalf("wordpress without scope: %d %v", rec.Code, out["options"])
	}
	for name, body := range map[string]map[string]any{
		"exact":    {"name": "ex", "strategy": "exact", "options": with(map[string]any{"baseUrl": "https://start.exactonline.nl"})},
		"evernote": {"name": "en", "strategy": "evernote", "options": with(nil)},
	} {
		rec, out := e.do("POST", connBase, body)
		if _, has := out["options"].(map[string]any)["scope"]; rec.Code != 201 || has {
			t.Fatalf("%s: %d %v", name, rec.Code, out["options"])
		}
	}
	if rec, _ := e.do("POST", connBase, map[string]any{"name": "ex2", "strategy": "exact", "options": with(map[string]any{"baseUrl": "https://evil.example"})}); rec.Code != 400 {
		t.Fatalf("exact bad baseUrl: %d", rec.Code)
	}
}

// TestMgmtRetiredConnections: retired strategies create, read and PATCH
// normally (LR39d-3).
func TestMgmtRetiredConnections(t *testing.T) {
	e := newConnEnv(t)
	for _, strategy := range []string{"fitbit", "instagram"} {
		rec, out := e.do("POST", connBase, map[string]any{"name": strategy, "strategy": strategy, "options": map[string]any{"client_id": "cid", "client_secret": "retired-throwaway-secret", "scope": []any{"profile"}}})
		if rec.Code != 201 {
			t.Fatalf("%s create: %d %s", strategy, rec.Code, rec.Body)
		}
		id := out["id"].(string)
		if rec, _ := e.do("GET", connBase+"/"+id, nil); rec.Code != 200 {
			t.Fatalf("%s read: %d", strategy, rec.Code)
		}
		if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": map[string]any{"client_id": "cid", "scope": []any{"activity"}}}); rec.Code != 200 {
			t.Fatalf("%s patch: %d %s", strategy, rec.Code, rec.Body)
		}
	}
}
