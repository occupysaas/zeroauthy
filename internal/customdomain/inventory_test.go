package customdomain

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestDomainInventory(t *testing.T) {
	b, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv struct {
		Operations []struct {
			ID, Path, Method, Scope string
			Status                  int
			Request, Response       []string
		}
		Enums        map[string][]string
		Limits       map[string]int
		PublicFields []string `json:"public_fields"`
	}
	if err := json.Unmarshal(b, &inv); err != nil {
		t.Fatal(err)
	}
	if len(inv.Operations) != 9 {
		t.Fatalf("operations: %d", len(inv.Operations))
	}
	seen := map[string]bool{}
	for i, op := range inv.Operations {
		if seen[op.ID] || op.ID == "" || op.Scope == "" {
			t.Fatalf("invalid operation: %+v", op)
		}
		seen[op.ID] = true
		if op.Path == "/custom-domains/{id}" && i < 4 {
			t.Fatal("default literal must precede parameter route")
		}
		if op.Method == "POST" && op.Path == "/custom-domains" && op.Status != 201 {
			t.Fatal("create status")
		}
		if op.Method == "DELETE" && op.Status != 204 {
			t.Fatal("delete status")
		}
		if op.Path == "/custom-domains/default" && !slices.Contains(op.Response, "domain") {
			t.Fatal("canonical response")
		}
		if op.Path == "/custom-domains/default" && op.Method == "PATCH" && !slices.Equal(op.Request, []string{"domain"}) {
			t.Fatal("default input")
		}
	}
	if slices.Contains(inv.PublicFields, "cname_api_key") {
		t.Fatal("secret in read projection")
	}
	for k, want := range map[string][]string{"verification_method": {"txt"}, "tls_policy": {"recommended"}, "custom_client_ip_header": {"true-client-ip", "cf-connecting-ip", "x-forwarded-for", "x-azure-clientip", ""}} {
		if !slices.Equal(inv.Enums[k], want) {
			t.Fatalf("enum %s: %v", k, inv.Enums[k])
		}
	}
	for k, want := range map[string]int{"domains": 100, "body_bytes": 65536, "metadata_properties": 10, "metadata_value_characters": 255, "hostname_bytes": 253, "label_bytes": 63, "query_bytes": 1024, "query_terms": 8} {
		if inv.Limits[k] != want {
			t.Fatalf("limit %s", k)
		}
	}
}
