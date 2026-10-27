package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const socialSecret = "do-not-log-provider-secret"

func socialBodies() map[string]map[string]any {
	return map[string]map[string]any{
		"google-oauth2": {"name": "goog", "strategy": "google-oauth2",
			"options": map[string]any{"client_id": "g-client", "client_secret": socialSecret, "icon_url": "https://cdn.example/g.png"}},
		"oauth2": {"name": "prov", "strategy": "oauth2", "options": map[string]any{
			"client_id": "o-client", "client_secret": socialSecret, "authorizationURL": "https://provider.example/authorize",
			"tokenURL": "https://provider.example/token", "scope": "read profile",
			"scripts": map[string]any{"fetchUserProfile": "function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'x'}) }"}}},
		"oidc": {"name": "corp", "strategy": "oidc", "options": map[string]any{
			"type": "back_channel", "client_id": "i-client", "client_secret": socialSecret,
			"discovery_url": "https://idp.example/.well-known/openid-configuration", "scopes": "openid profile"}},
	}
}

func (e *connEnv) stored(id string) *store.Connection {
	e.t.Helper()
	c, err := e.st.Connections().Get(context.Background(), e.tenant.ID, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func noSecret(t *testing.T, what, body string) {
	t.Helper()
	if strings.Contains(body, socialSecret) || strings.Contains(body, "client_secret") {
		t.Fatalf("%s exposes the provider secret: %s", what, body)
	}
}

func TestSocialConnectionsContract(t *testing.T) { socialConnectionsContract(t, socialBodies()) }
func TestMicrosoftConnectionsContract(t *testing.T) {
	bodies := map[string]map[string]any{}
	for _, strategy := range []string{"windowslive", "waad"} {
		options := map[string]any{"client_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "client_secret": socialSecret}
		if strategy == "waad" {
			options["tenant_domain"] = "Contoso.Example"
			options["domain"] = "Display only"
		}
		bodies[strategy] = map[string]any{"name": strategy, "strategy": strategy, "options": options}
	}
	socialConnectionsContract(t, bodies)
}
func socialConnectionsContract(t *testing.T, bodies map[string]map[string]any) {
	for strategy, body := range bodies {
		t.Run(strategy, func(t *testing.T) {
			e := newConnEnv(t)
			app := e.createClient("social-app")
			body["enabled_clients"] = []string{app}
			rec, out := e.do("POST", connBase, body)
			if rec.Code != 201 {
				t.Fatalf("create = %d %s", rec.Code, rec.Body)
			}
			noSecret(t, "create", rec.Body.String())
			id := out["id"].(string)
			if out["strategy"] != strategy || toMap(out["options"])["client_id"] == nil {
				t.Fatalf("create view %v", out)
			}
			for _, k := range []string{"password_options", "brute_force_protection", "enabledDatabaseCustomization", "requires_username", "mfa"} {
				if _, ok := toMap(out["options"])[k]; ok {
					t.Errorf("database option %q on a %s connection", k, strategy)
				}
			}
			c := e.stored(id)
			if len(c.FederationSecretsSealed) == 0 || c.FederationRevision != 1 {
				t.Fatalf("stored secret/revision %d %d", len(c.FederationSecretsSealed), c.FederationRevision)
			}
			if _, ok := c.Extra["client_secret"]; ok || strings.Contains(toJSON(c.Extra), socialSecret) {
				t.Fatal("plaintext secret stored in Extra")
			}
			creds, err := federation.OpenCredentials(e.w, e.tenant.ID, id, c.FederationSecretsSealed)
			if err != nil || creds.ClientSecret != socialSecret {
				t.Fatalf("sealed credentials %v %v", creds.ClientSecret == socialSecret, err)
			}
			if _, err := federation.OpenCredentials(e.w, e.tenant.ID, "con_other", c.FederationSecretsSealed); err == nil {
				t.Fatal("credentials open under another connection")
			}

			// Every read projection omits the secret.
			for _, target := range []string{connBase + "/" + id, connBase, connBase + "?strategy=" + strategy,
				connBase + "?take=1", connBase + "?fields=options&include_fields=true"} {
				rec, _ := e.do("GET", target, nil)
				if rec.Code != 200 {
					t.Fatalf("%s = %d %s", target, rec.Code, rec.Body)
				}
				noSecret(t, target, rec.Body.String())
			}
			rec, page := e.do("GET", connBase+"?take=1&include_totals=true", nil)
			if rec.Code != 200 || page["connections"] == nil || page["total"] != nil {
				t.Fatalf("checkpoint page %d %v", rec.Code, page)
			}

			// PATCH options without the secret preserves it; a nonsecret
			// change moves the revision.
			opts := toMap(out["options"])
			if strategy == "oidc" {
				opts["scopes"] = "openid profile email"
			} else if strategy == "oauth2" {
				opts["scope"] = "read"
			} else if strategy == "windowslive" || strategy == "waad" {
				opts["set_user_root_attributes"] = "on_first_login"
			} else {
				opts["email"] = false
			}
			opts["unknown_inert"] = "kept"
			rec, patched := e.do("PATCH", connBase+"/"+id, map[string]any{"options": opts})
			if rec.Code != 200 {
				t.Fatalf("patch = %d %s", rec.Code, rec.Body)
			}
			noSecret(t, "patch", rec.Body.String())
			if toMap(patched["options"])["unknown_inert"] != "kept" {
				t.Fatalf("inert option lost: %v", patched["options"])
			}
			after := e.stored(id)
			if string(after.FederationSecretsSealed) != string(c.FederationSecretsSealed) || after.FederationRevision != 2 {
				t.Fatalf("secret preserved=%v revision=%d", string(after.FederationSecretsSealed) == string(c.FederationSecretsSealed), after.FederationRevision)
			}

			fresh := func() map[string]any {
				var m map[string]any
				_ = json.Unmarshal([]byte(toJSON(patched["options"])), &m)
				return m
			}
			// Rejected changes leave the revision intact.
			if strategy == "windowslive" || strategy == "waad" {
				for _, key := range []string{"ext_groups", "trust_email_verified", "domain_aliases", "offline_access"} {
					o := fresh()
					o[key] = true
					if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o}); rec.Code != 400 {
						t.Fatalf("accepted %s: %d", key, rec.Code)
					}
				}
			}
			for name, change := range map[string]map[string]any{
				"empty secret": {"client_secret": ""},
				"null secret":  {"client_secret": nil},
				"client_id":    {"client_id": "other"},
			} {
				o := fresh()
				for k, v := range change {
					o[k] = v
				}
				rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o})
				if rec.Code != 400 {
					t.Errorf("%s = %d %s", name, rec.Code, rec.Body)
				}
			}
			o := fresh()
			delete(o, "client_id")
			if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o}); rec.Code != 400 {
				t.Errorf("omitted immutable client_id = %d", rec.Code)
			}
			if strategy != "google-oauth2" {
				o := fresh()
				if strategy == "oidc" {
					o["discovery_url"] = "https://other.example/.well-known/openid-configuration"
				} else {
					o["tokenURL"] = "https://other.example/token"
				}
				if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o}); rec.Code != 400 {
					t.Errorf("changed endpoint binding = %d %s", rec.Code, rec.Body)
				}
			}
			if strategy == "oauth2" {
				o := fresh()
				toMap(o["scripts"])["fetchUserProfile"] = "function fetchUserProfile(a, c, cb) { cb(null, {user_id: 'y'}) }"
				if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o}); rec.Code != 400 {
					t.Errorf("changed script = %d", rec.Code)
				}
			}
			if got := e.stored(id).FederationRevision; got != 2 {
				t.Fatalf("rejected changes moved the revision to %d", got)
			}

			// Secret rotation re-seals and moves the revision.
			o = fresh()
			o["client_secret"] = "rotated-secret"
			if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"options": o}); rec.Code != 200 {
				t.Fatalf("rotate = %d %s", rec.Code, rec.Body)
			}
			rot := e.stored(id)
			creds, _ = federation.OpenCredentials(e.w, e.tenant.ID, id, rot.FederationSecretsSealed)
			if creds.ClientSecret != "rotated-secret" || rot.FederationRevision != 3 {
				t.Fatalf("rotation %v revision %d", creds.ClientSecret == "rotated-secret", rot.FederationRevision)
			}

			// Disabling authentication and changing enablement are effective.
			if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"authentication": map[string]any{"active": false}}); rec.Code != 200 {
				t.Fatalf("disable = %d %s", rec.Code, rec.Body)
			}
			if got := e.stored(id).FederationRevision; got != 4 {
				t.Fatalf("disable revision %d", got)
			}
			if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"authentication": map[string]any{"enabled": true}}); rec.Code != 400 {
				t.Errorf("authentication alias = %d", rec.Code)
			}
			rec, _ = e.doAny("PATCH", connBase+"/"+id+"/clients", []map[string]any{{"client_id": app, "status": false}})
			if rec.Code != 204 {
				t.Fatalf("disable client = %d %s", rec.Code, rec.Body)
			}
			if got := e.stored(id).FederationRevision; got != 5 {
				t.Fatalf("enablement revision %d", got)
			}
			if rec, _ := e.do("PATCH", connBase+"/"+id, map[string]any{"display_name": "Shown"}); rec.Code != 200 {
				t.Fatalf("display = %d", rec.Code)
			}
			if got := e.stored(id).FederationRevision; got != 5 {
				t.Fatalf("display-only change moved the revision to %d", got)
			}
			if rec, _ := e.do("DELETE", connBase+"/"+id, nil); rec.Code != 202 {
				t.Fatalf("delete = %d %s", rec.Code, rec.Body)
			}
			if rec, _ := e.do("GET", connBase+"/"+id, nil); rec.Code != 404 {
				t.Fatalf("deleted connection read = %d", rec.Code)
			}
		})
	}
}

func TestSocialConnectionsValidation(t *testing.T) {
	e := newConnEnv(t)
	for name, body := range map[string]map[string]any{
		"missing secret":   {"name": "a", "strategy": "google-oauth2", "options": map[string]any{"client_id": "c"}},
		"front channel":    {"name": "b", "strategy": "oidc", "options": map[string]any{"type": "front_channel", "client_id": "c", "client_secret": "s", "discovery_url": "https://idp.example/d", "scopes": "openid"}},
		"pipe name":        {"name": "a|b", "strategy": "google-oauth2", "options": map[string]any{"client_id": "c", "client_secret": "s"}},
		"assurance prompt": {"name": "d", "strategy": "google-oauth2", "options": map[string]any{"client_id": "c", "client_secret": "s", "upstream_params": map[string]any{"prompt": map[string]any{"value": "login"}}}},
		"private endpoint": {"name": "e", "strategy": "oauth2", "options": map[string]any{"client_id": "c", "client_secret": "s", "authorizationURL": "https://10.0.0.1/a", "tokenURL": "https://p.example/t", "scope": "x", "scripts": map[string]any{"fetchUserProfile": "f"}}},
	} {
		if o := toMap(body["options"]); o["client_secret"] != nil {
			o["client_secret"] = socialSecret
		}
		rec, out := e.do("POST", connBase, body)
		wantError(t, name, rec, out, 400, "invalid_body")
		if strings.Contains(rec.Body.String(), socialSecret) {
			t.Errorf("%s echoes the secret: %s", name, rec.Body)
		}
	}
}

// PinIssuer pins the OIDC issuer once, under a revision compare-and-swap.
func TestSocialIssuerPin(t *testing.T) {
	e := newConnEnv(t)
	_, out := e.do("POST", connBase, socialBodies()["oidc"])
	id := out["id"].(string)
	ctx := context.Background()
	if _, err := federation.PinIssuer(ctx, e.st, e.tenant.ID, id, 0, "https://idp.example"); err == nil {
		t.Fatal("stale revision pinned")
	}
	rev, err := federation.PinIssuer(ctx, e.st, e.tenant.ID, id, 1, "https://idp.example")
	if err != nil || rev != 2 {
		t.Fatalf("pin %d %v", rev, err)
	}
	if _, err := federation.PinIssuer(ctx, e.st, e.tenant.ID, id, 2, "https://evil.example"); err == nil {
		t.Fatal("pinned issuer replaced")
	}
	if rev, err := federation.PinIssuer(ctx, e.st, e.tenant.ID, id, 2, "https://idp.example"); err != nil || rev != 2 {
		t.Fatalf("repeat pin %d %v", rev, err)
	}
	rec, view := e.do("GET", connBase+"/"+id, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "federation_issuer") {
		t.Fatalf("issuer leaks into the view: %v", view)
	}
}
