package server

import (
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

func TestMgmtGitHubConnections(t *testing.T) {
	e := newConnEnv(t)
	const secret = "gh-throwaway-secret-value"
	options := func(secret any, extra map[string]any) map[string]any {
		o := map[string]any{"client_id": "Iv1.example", "read_user": true}
		if secret != nil {
			o["client_secret"] = secret
		}
		for k, v := range extra {
			o[k] = v
		}
		return o
	}
	rec, out := e.do("POST", connBase, map[string]any{"name": "github", "strategy": "github", "options": options(secret, nil)})
	if rec.Code != 201 {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "client_secret") {
		t.Fatal("response exposes client_secret")
	}
	scope, _ := out["options"].(map[string]any)["scope"].([]any)
	if len(scope) != 2 || scope[0] != "user:email" || scope[1] != "read:user" {
		t.Fatalf("effective scope not returned: %v", out["options"])
	}
	id := out["id"].(string)
	if e.stored(id).FederationRevision != 1 {
		t.Fatalf("revision=%d", e.stored(id).FederationRevision)
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(e.stored(id)))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsSocial || cfg.AuthorizationURL != rules.GitHubAuthorizationURL || cfg.TokenURL != rules.GitHubTokenURL || cfg.DiscoveryURL != "" || cfg.Issuer != "" || len(cfg.Scopes) != 2 {
		t.Fatalf("runtime configuration: %+v", cfg)
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
	patch(options(nil, map[string]any{"repo": true}), 200)
	if e.stored(id).FederationRevision != 2 {
		t.Fatalf("scope change revision=%d", e.stored(id).FederationRevision)
	}
	changed := options(nil, nil)
	changed["client_id"] = "Iv1.changed"
	patch(changed, 400)
	patch(options("", nil), 400)
	if e.stored(id).FederationRevision != 2 {
		t.Fatal("rejected PATCH changed the revision")
	}
}
