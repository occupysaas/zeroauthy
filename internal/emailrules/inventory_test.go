package emailrules

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEmailInventoryComplete(t *testing.T) {
	data, err := os.ReadFile("inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Operations []struct {
			Method, Route, Scope, SDK, Source string
			Status                            int
		} `json:"operations"`
		Providers []struct {
			Name       string `json:"name"`
			Executable bool   `json:"executable"`
			Source     string `json:"source"`
			VendorDoc  string `json:"vendor_doc"`
		} `json:"providers"`
		Templates      []string `json:"templates"`
		TemplateFields []string `json:"template_fields"`
	}
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Operations) != 8 {
		t.Fatalf("operations = %d, want 8", len(inventory.Operations))
	}
	seenRoutes := map[string]bool{}
	for _, op := range inventory.Operations {
		key := op.Method + " " + op.Route
		if op.Method == "" || op.Route == "" || op.Scope == "" || op.SDK == "" || op.Source == "" || op.Status == 0 {
			t.Errorf("incomplete operation: %+v", op)
		}
		if seenRoutes[key] {
			t.Errorf("duplicate operation %s", key)
		}
		seenRoutes[key] = true
	}
	if len(inventory.Templates) != 14 {
		t.Fatalf("templates = %d, want 14", len(inventory.Templates))
	}
	seenTemplates := map[string]bool{}
	for _, name := range inventory.Templates {
		if name == "" || seenTemplates[name] {
			t.Errorf("empty or duplicate template name %q", name)
		}
		seenTemplates[name] = true
	}
	if !seenTemplates["auth_email_by_code"] {
		t.Error("auth_email_by_code missing")
	}
	if len(inventory.Providers) != 10 {
		t.Fatalf("providers = %d, want 9 executable plus custom", len(inventory.Providers))
	}
	seenProviders := map[string]bool{}
	executable := 0
	customExecutable := false
	for _, p := range inventory.Providers {
		if p.Name == "" || p.Source == "" || seenProviders[p.Name] {
			t.Errorf("empty, unsourced or duplicate provider: %+v", p)
		}
		seenProviders[p.Name] = true
		if p.Executable {
			executable++
		}
		if p.Name != "custom" && p.VendorDoc == "" {
			t.Errorf("provider %s has no official protocol source", p.Name)
		}
		if p.Name == "custom" && p.Executable {
			customExecutable = true
		}
	}
	if executable != 10 || !customExecutable || !seenProviders["custom"] {
		t.Errorf("executable providers = %d; custom must be executable", executable)
	}
	seenFields := map[string]bool{}
	for _, field := range inventory.TemplateFields {
		if field == "" || seenFields[field] {
			t.Errorf("empty or duplicate template schema field %q", field)
		}
		seenFields[field] = true
	}
}
