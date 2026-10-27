package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestFederationSecretReinjection(t *testing.T) {
	const script = "function fetchUserProfile(accessToken, context, callback) { callback(null, {user_id: 'subject'}); }"
	rows := []map[string]any{}
	credentials := map[string]string{}
	for _, strategy := range []string{"google-oauth2", "oauth2", "oidc", "windowslive", "waad"} {
		options := map[string]any{"client_id": "upstream"}
		if strategy == "oauth2" {
			options["scripts"] = map[string]any{"fetchUserProfile": "scripts/profile.js"}
		}
		rows = append(rows, map[string]any{"name": strategy, "strategy": strategy, "options": options, "enabled_clients": []string{"Application"}})
		credentials[strategy] = "private-fixture-secret"
	}
	b, _ := json.Marshal(rows)
	export := deploymigration.Export{Resources: map[string]json.RawMessage{"connections": b}, Files: map[string][]byte{"scripts/profile.js": []byte(script)}}
	for _, missing := range []string{"google-oauth2", "oauth2", "oidc", "windowslive", "waad"} {
		creds := map[string]string{}
		for k, v := range credentials {
			if k != missing {
				creds[k] = v
			}
		}
		if _, err := deploymigration.FederationImport(export, creds); err == nil || strings.Contains(err.Error(), "private-fixture-secret") {
			t.Fatal("missing explicit injection must fail sanitized")
		}
	}
	imported, err := deploymigration.FederationImport(export, credentials)
	if err != nil {
		t.Fatal(err)
	}
	var actual []map[string]any
	_ = json.Unmarshal(imported, &actual)
	if len(actual) != 5 {
		t.Fatal("strategies lost")
	}
	for _, row := range actual {
		o := row["options"].(map[string]any)
		if o["client_secret"] != "private-fixture-secret" {
			t.Fatal("provider secret lost")
		}
		if row["strategy"] == "oauth2" && o["scripts"].(map[string]any)["fetchUserProfile"] != script {
			t.Fatal("script bytes lost")
		}
	}
	if strings.Contains(string(export.Resources["connections"]), "private-fixture-secret") {
		t.Fatal("normal export mutated")
	}
	delete(export.Files, "scripts/profile.js")
	if _, err := deploymigration.FederationImport(export, credentials); err == nil {
		t.Fatal("missing script accepted")
	}
}

func TestOAuthMaterializedAndInlineScripts(t *testing.T) {
	for _, format := range []string{"yaml", "directory"} {
		t.Run(format, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "tenant.yaml")
			body := `connections: [{name: oauth, strategy: oauth2, options: {scripts: {fetchUserProfile: "scripts/profile.js"}}}]`
			if format == "directory" {
				if err := os.Mkdir(filepath.Join(root, "connections"), 0700); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(root, "connections/oauth.json")
				body = `{"name":"oauth","strategy":"oauth2","options":{"scripts":{"fetchUserProfile":"scripts/profile.js"}}}`
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			input := path
			if format == "directory" {
				input = root
			}
			if _, err := load(input, format); err == nil {
				t.Fatal("missing external OAuth script accepted")
			}
			_ = os.Mkdir(filepath.Join(root, "scripts"), 0700)
			script := []byte("function fetchUserProfile(a, c, cb) { cb(null, {user_id:'x'}); }\n")
			_ = os.WriteFile(filepath.Join(root, "scripts/profile.js"), script, 0600)
			e, err := load(input, format)
			if err != nil {
				t.Fatal(err)
			}
			if string(e.Files["scripts/profile.js"]) != string(script) {
				t.Fatal("external bytes not retained")
			}
			// Real pinned CLI exports inline script strings before our materialization.
			_ = os.WriteFile(path, []byte(strings.ReplaceAll(body, "scripts/profile.js", string(script[:len(script)-1]))), 0600)
			if _, err := load(input, format); err != nil {
				t.Fatalf("inline OAuth script interpreted as file: %v", err)
			}
		})
	}
}

func TestCompareFederationRejectsDroppedStrategiesOptionsAndClients(t *testing.T) {
	m := Manifest{Resources: []ManifestResource{{Name: "clients", Status: "included"}, {Name: "connections", Status: "included"}}}
	source := deploymigration.Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"old","name":"Application"}]`), "connections": json.RawMessage(`[{"name":"personal","strategy":"windowslive","options":{"strategy_version":2},"enabled_clients":["old"]},{"name":"single","strategy":"waad","options":{"useCommonEndpoint":false,"tenant_domain":"directory.test"},"enabled_clients":["old"]},{"name":"organizations","strategy":"waad","options":{"useCommonEndpoint":true},"enabled_clients":["old"]}]`)}}
	for _, mutation := range []string{"strategy", "option", "client", "mode", "connection"} {
		t.Run(mutation, func(t *testing.T) {
			target := deploymigration.Export{Resources: map[string]json.RawMessage{"clients": source.Resources["clients"], "connections": append(json.RawMessage(nil), source.Resources["connections"]...)}}
			if !Compare(source, target, m, Domains{}).Equivalent {
				t.Fatal("baseline differs")
			}
			var rows []map[string]any
			_ = json.Unmarshal(target.Resources["connections"], &rows)
			switch mutation {
			case "strategy":
				rows[0]["strategy"] = "google-oauth2"
			case "option":
				delete(rows[0]["options"].(map[string]any), "strategy_version")
			case "client":
				rows[0]["enabled_clients"] = []string{}
			case "mode":
				rows[1]["options"].(map[string]any)["useCommonEndpoint"] = true
			case "connection":
				rows = rows[:2]
			}
			target.Resources["connections"], _ = json.Marshal(rows)
			if Compare(source, target, m, Domains{}).Equivalent {
				t.Fatal("federation data loss normalized away")
			}
		})
	}
}
