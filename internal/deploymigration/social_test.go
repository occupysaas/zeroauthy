package deploymigration

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDeployMigrationSocial(t *testing.T) {
	export := func(options string) Export {
		return Export{Resources: map[string]json.RawMessage{"connections": json.RawMessage(`[{"name":"amazon","strategy":"amazon","options":` + options + `}]`)}}
	}
	if _, err := FederationImport(export(`{"client_id":"amzn1.example","client_secret":"********"}`), map[string]string{"amazon": "amz-throwaway-secret"}); err == nil || strings.Contains(err.Error(), "amz-throwaway") {
		t.Fatalf("masked exported secret accepted or leaked: %v", err)
	}
	raw, err := FederationImport(export(`{"client_id":"amzn1.example","postal_code":true,"scope":["profile","postal_code"]}`), map[string]string{"amazon": "amz-throwaway-secret"})
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Options map[string]any }
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if o := rows[0].Options; o["client_secret"] != "amz-throwaway-secret" || o["postal_code"] != true {
		t.Fatalf("options not preserved: %v", o)
	}
	_, err = FederationImport(export(`{"client_id":"amzn1.example","scope":["profile","extra"]}`), map[string]string{"amazon": "amz-throwaway-secret"})
	if err == nil || !strings.Contains(err.Error(), "options.scope must match") || strings.Contains(err.Error(), "amz-throwaway") {
		t.Fatalf("mismatched scope: %v", err)
	}
}
