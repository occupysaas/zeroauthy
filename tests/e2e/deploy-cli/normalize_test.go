package main

import (
	"encoding/json"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/deploymigration"
)

func TestCompareRoundTrip(t *testing.T) {
	source := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         json.RawMessage(`[{"client_id":"c-old","name":"App","app_type":"spa"}]`),
		"resourceServers": json.RawMessage(`[{"id":"api-old","name":"API","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"id":"g-old","client_id":"c-old","audience":"api-old","scopes":["read","write"]}]`),
	}}
	target := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         json.RawMessage(`[{"client_id":"c-new","name":"App","app_type":"spa"}]`),
		"resourceServers": json.RawMessage(`[{"id":"api-new","name":"API","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"id":"g-new","client_id":"c-new","audience":"api-new","scopes":["read","write"]}]`),
	}}
	r := Compare(source, target, testManifest(), Domains{})
	if !r.Equivalent {
		t.Fatalf("equivalent import rejected: %+v", r.Differences)
	}
}

func TestCompareClientsWithoutNameMatchByClientID(t *testing.T) {
	client := json.RawMessage(`[{"client_id":"e2e-cli-admin","app_type":"non_interactive"}]`)
	source := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         client,
		"resourceServers": json.RawMessage(`[{"id":"api","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"client_id":"e2e-cli-admin","audience":"api","scopes":["read"]}]`),
	}}
	target := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         client,
		"resourceServers": json.RawMessage(`[{"id":"api","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"client_id":"e2e-cli-admin","audience":"api","scopes":["read"]}]`),
	}}
	if r := Compare(source, target, testManifest(), Domains{}); !r.Equivalent {
		t.Fatalf("same client ID without name rejected: %+v", r.Differences)
	}
}

func TestCompareRejectsLostScope(t *testing.T) {
	s := deploymigration.Export{Resources: map[string]json.RawMessage{"clientGrants": json.RawMessage(`[{"client_id":"c","audience":"api","scopes":["read","write"]}]`)}}
	target := deploymigration.Export{Resources: map[string]json.RawMessage{"clientGrants": json.RawMessage(`[{"client_id":"c","audience":"api","scopes":["read"]}]`)}}
	r := Compare(s, target, testManifest(), Domains{})
	if r.Equivalent {
		t.Fatal("lost scope was normalized away")
	}
}

func TestCompareIncludesScriptHashes(t *testing.T) {
	s := deploymigration.Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"c","name":"App","app_type":"spa"}]`), "resourceServers": json.RawMessage(`[{"id":"api","name":"API","identifier":"https://api.test"}]`), "clientGrants": json.RawMessage(`[{"client_id":"c","audience":"api","scopes":["read"]}]`)}, Files: map[string][]byte{"scripts/db.js": []byte("one")}}
	target := s
	target.Files = map[string][]byte{"scripts/db.js": []byte("two")}
	r := Compare(s, target, testManifest(), Domains{})
	if r.Equivalent {
		t.Fatal("changed script hash was ignored")
	}
}

func TestCompareRejectsSecretsAndUnknownFieldChanges(t *testing.T) {
	source := deploymigration.Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"c","name":"App","app_type":"spa"}]`), "resourceServers": json.RawMessage(`[{"id":"api","name":"API","identifier":"https://api.test"}]`), "clientGrants": json.RawMessage(`[{"client_id":"c","audience":"api","scopes":["read"]}]`)}}
	target := deploymigration.Export{Resources: map[string]json.RawMessage{"clients": json.RawMessage(`[{"client_id":"c2","name":"App","app_type":"spa","client_secret":"********"}]`), "resourceServers": json.RawMessage(`[{"id":"api","name":"API","identifier":"https://api.test"}]`), "clientGrants": json.RawMessage(`[{"client_id":"c2","audience":"api","scopes":["read"]}]`)}}
	if Compare(source, target, testManifest(), Domains{}).Equivalent {
		t.Fatal("secret placeholder was ignored")
	}
	target.Resources["clients"] = json.RawMessage(`[{"client_id":"c2","name":"App","app_type":"spa","mystery":"value"}]`)
	if Compare(source, target, testManifest(), Domains{}).Equivalent {
		t.Fatal("unknown field difference was ignored")
	}
}

func testManifest() Manifest {
	return Manifest{ToolVersion: "9.1.0", Resources: []ManifestResource{{Name: "clients", Status: "included"}, {Name: "resourceServers", Status: "included"}, {Name: "clientGrants", Status: "included"}}, Normalizations: []Normalization{{Resource: "clients", Path: "client_id", Rule: "reference-map"}, {Resource: "resourceServers", Path: "id", Rule: "reference-map"}, {Resource: "clientGrants", Path: "id", Rule: "reference-map"}, {Resource: "clientGrants", Path: "client_id", Rule: "reference-map"}, {Resource: "clientGrants", Path: "audience", Rule: "reference-map"}}}
}
