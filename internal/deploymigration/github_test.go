package deploymigration

import (
	"encoding/json"
	"strings"
	"testing"
)

func githubExport(options string) Export {
	return Export{Resources: map[string]json.RawMessage{"connections": json.RawMessage(`[{"name":"github","strategy":"github","options":` + options + `}]`)}}
}

func TestDeployMigrationGitHub(t *testing.T) {
	// The masked exported secret is never accepted; the operator injects it.
	masked := githubExport(`{"client_id":"Iv1.example","client_secret":"********","read_user":true}`)
	if _, err := FederationImport(masked, map[string]string{"github": "gh-throwaway-secret"}); err == nil || strings.Contains(err.Error(), "gh-throwaway") {
		t.Fatalf("masked exported secret accepted or leaked: %v", err)
	}
	if _, err := FederationImport(githubExport(`{"client_id":"Iv1.example","read_user":true}`), nil); err == nil {
		t.Fatal("missing injected secret accepted")
	}

	// Flags round-trip and the secret lands in client_secret, not app_secret.
	raw, err := FederationImport(githubExport(`{"client_id":"Iv1.example","email":false,"read_user":true,"repo_status":true,"scope":["read:user","repo:status"]}`), map[string]string{"github": "gh-throwaway-secret"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Options map[string]any }
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	o := rows[0].Options
	if o["client_secret"] != "gh-throwaway-secret" || o["app_secret"] != nil || o["email"] != false || o["read_user"] != true || o["repo_status"] != true {
		t.Fatalf("options not preserved: %v", o)
	}

	// A scope that disagrees with the flags names the expected scope.
	_, err = FederationImport(githubExport(`{"client_id":"Iv1.example","read_user":true,"scope":["user:email","repo"]}`), map[string]string{"github": "gh-throwaway-secret"})
	if err == nil || !strings.Contains(err.Error(), "options.scope must match") || !strings.Contains(err.Error(), "user:email read:user") || strings.Contains(err.Error(), "gh-throwaway") {
		t.Fatalf("mismatched scope: %v", err)
	}
}
