package main

import (
	"encoding/json"
	"strings"
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

func TestCompareEmailResourcesStrictly(t *testing.T) {
	source := comparisonFixture()
	target := comparisonFixture()
	source.Resources["emailProvider"] = json.RawMessage(`{"name":"smtp","enabled":true,"default_from_address":"mail@example.test"}`)
	target.Resources["emailProvider"] = json.RawMessage(`{"name":"smtp","enabled":true,"default_from_address":"mail@example.test"}`)
	source.Resources["emailTemplates"] = json.RawMessage(`[{"template":"verify_email","enabled":true,"subject":"Verify","body":"Hello"}]`)
	target.Resources["emailTemplates"] = json.RawMessage(`[{"template":"verify_email","enabled":true,"subject":"Verify","body":"Hello"}]`)
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "emailProvider", Status: "included"}, ManifestResource{Name: "emailTemplates", Status: "included"})
	if !Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("equal email resources differ")
	}
	target.Resources["emailProvider"] = json.RawMessage(`{"name":"smtp","enabled":false,"default_from_address":"mail@example.test"}`)
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("changed provider setting was normalized away")
	}
	target.Resources["emailProvider"] = source.Resources["emailProvider"]
	target.Resources["emailTemplates"] = json.RawMessage(`[{"template":"verify_email","enabled":true,"subject":"Different","body":"Hello"}]`)
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("changed template was normalized away")
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

func TestCompareClientsFallBackToNameWhenClientIDIsAbsent(t *testing.T) {
	export := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         json.RawMessage(`[{"name":"Deploy fixture","app_type":"spa"}]`),
		"resourceServers": json.RawMessage(`[{"id":"api","name":"API","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"client_id":"Deploy fixture","audience":"api","scopes":["read"]}]`),
	}}
	if r := Compare(export, export, testManifest(), Domains{}); !r.Equivalent {
		t.Fatalf("same named client without ID rejected: %+v", r.Differences)
	}
}

func TestCompareResourceServersFallBackToIdentifierWhenIDIsAbsent(t *testing.T) {
	export := deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         json.RawMessage(`[{"client_id":"client","name":"App","app_type":"spa"}]`),
		"resourceServers": json.RawMessage(`[{"identifier":"https://api.test","name":"API"}]`),
		"clientGrants":    json.RawMessage(`[{"client_id":"client","audience":"https://api.test","scopes":["read"]}]`),
	}}
	if r := Compare(export, export, testManifest(), Domains{}); !r.Equivalent {
		t.Fatalf("same API identifier without ID rejected: %+v", r.Differences)
	}
}

func comparisonFixture() deploymigration.Export {
	return deploymigration.Export{Resources: map[string]json.RawMessage{
		"clients":         json.RawMessage(`[{"client_id":"c","name":"App","app_type":"spa","callbacks":["https://a.test","https://b.test"]}]`),
		"resourceServers": json.RawMessage(`[{"id":"api","identifier":"https://api.test"}]`),
		"clientGrants":    json.RawMessage(`[{"client_id":"c","audience":"api","scope":["read","write"]}]`),
	}}
}
func TestCompareRejectsLostScope(t *testing.T) {
	source, target := comparisonFixture(), comparisonFixture()
	if !Compare(source, target, testManifest(), Domains{}).Equivalent {
		t.Fatal("baseline must be equivalent")
	}
	target.Resources["clientGrants"] = json.RawMessage(`[{"client_id":"c","audience":"api","scope":["read"]}]`)
	r := Compare(source, target, testManifest(), Domains{})
	if r.Equivalent {
		t.Fatal("lost scope was normalized away")
	}
	for _, d := range r.Differences {
		if d.Resource != "clientGrants" {
			t.Fatalf("unrelated failure: %+v", d)
		}
	}
}

func TestCompareRejectsDataLoss(t *testing.T) {
	for _, tc := range []struct{ name, resource, changed string }{
		{"empty", "clients", `[]`},
		{"duplicate name", "clients", `[{"client_id":"c","name":"App","app_type":"spa"},{"client_id":"other","name":"App","app_type":"spa"}]`},
		{"ordered callbacks", "clients", `[{"client_id":"c","name":"App","app_type":"spa","callbacks":["https://b.test","https://a.test"]}]`},
		{"unknown field", "clients", `[{"client_id":"c","name":"App","app_type":"spa","mystery":true}]`},
		{"wrong grant client", "clientGrants", `[{"client_id":"another","audience":"api","scope":["read","write"]}]`},
		{"missing grant", "clientGrants", `[]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, target := comparisonFixture(), comparisonFixture()
			target.Resources[tc.resource] = json.RawMessage(tc.changed)
			if Compare(source, target, testManifest(), Domains{}).Equivalent {
				t.Fatal("data loss accepted")
			}
		})
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

func TestCompareRejectsSharedDanglingReferencesAndMaskedSecrets(t *testing.T) {
	for _, change := range []struct{ resource, raw string }{
		{"clientGrants", `[{"client_id":"missing","audience":"api","scope":["read"]}]`},
		{"clientGrants", `[{"client_id":"c","audience":"missing-api","scope":["read"]}]`},
		{"clients", `[{"client_id":"c","name":"App","app_type":"spa","client_secret":"********"}]`},
	} {
		source := comparisonFixture()
		source.Resources[change.resource] = json.RawMessage(change.raw)
		if Compare(source, source, testManifest(), Domains{}).Equivalent {
			t.Fatalf("invalid self-comparison accepted for %s", change.resource)
		}
	}
}
func TestCompareMapsStringConnectionReferences(t *testing.T) {
	source, target := comparisonFixture(), comparisonFixture()
	source.Resources["connections"] = json.RawMessage(`[{"id":"old","name":"Users","enabled_clients":["c"]}]`)
	target.Resources["clients"] = json.RawMessage(`[{"client_id":"new","name":"App","app_type":"spa","callbacks":["https://a.test","https://b.test"]}]`)
	target.Resources["clientGrants"] = json.RawMessage(`[{"client_id":"new","audience":"api","scope":["read","write"]}]`)
	target.Resources["connections"] = json.RawMessage(`[{"id":"new-con","name":"Users","enabled_clients":["new"]}]`)
	m := testManifest()
	m.Resources = append(m.Resources, ManifestResource{Name: "connections", Status: "included"})
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("valid connection mapping rejected: %+v", r.Differences)
	}
	target.Resources["connections"] = json.RawMessage(`[{"id":"new-con","name":"Users","enabled_clients":["missing"]}]`)
	if Compare(source, target, m, Domains{}).Equivalent {
		t.Fatal("wrong enabled client accepted")
	}
}

func TestCompareTreatsOnlyDeclaredScopeArraysAsSets(t *testing.T) {
	source, target := comparisonFixture(), comparisonFixture()
	target.Resources["clientGrants"] = json.RawMessage(`[{"client_id":"c","audience":"api","scope":["write","read"]}]`)
	if r := Compare(source, target, testManifest(), Domains{}); !r.Equivalent {
		t.Fatalf("reordered scope set rejected: %+v", r.Differences)
	}
	target.Resources["clients"] = json.RawMessage(`[{"client_id":"c","name":"App","app_type":"spa","callbacks":["https://b.test","https://a.test"]}]`)
	if Compare(source, target, testManifest(), Domains{}).Equivalent {
		t.Fatal("ordered callback change concealed")
	}
}

func TestCompareHostedResourcesStrictly(t *testing.T) {
	source, target := comparisonFixture(), comparisonFixture()
	m := testManifest()
	for name, raw := range map[string]string{
		"branding": `{"colors":{"primary":"#123456"}}`,
		"themes":   `[{"themeId":"old","displayName":"Example","colors":{"primary_button":"#123456"}}]`,
		"prompts":  `{"identifier_first":true,"customText":{"en":{"login":{"login":{"title":"Hello"}}}},"partials":{"login":{"login":{"form-footer-start":"<p>Footer</p>"}}}}`,
	} {
		source.Resources[name] = json.RawMessage(raw)
		target.Resources[name] = json.RawMessage(raw)
		m.Resources = append(m.Resources, ManifestResource{Name: name, Status: "included"})
	}
	m.Normalizations = append(m.Normalizations, Normalization{Resource: "themes", Path: "themeId", Rule: "reference-map", Reason: "Active default theme identity mapped by displayName"})
	target.Resources["themes"] = json.RawMessage(`[{"themeId":"new","displayName":"Example","colors":{"primary_button":"#123456"}}]`)
	if r := Compare(source, target, m, Domains{}); !r.Equivalent {
		t.Fatalf("equal hosted config differs: %+v", r.Differences)
	}
	for _, name := range []string{"branding", "themes", "prompts"} {
		saved := target.Resources[name]
		target.Resources[name] = json.RawMessage(strings.ReplaceAll(string(saved), "#123456", "#abcdef"))
		if name == "prompts" {
			target.Resources[name] = json.RawMessage(strings.ReplaceAll(string(saved), "Hello", "Changed"))
		}
		if Compare(source, target, m, Domains{}).Equivalent {
			t.Errorf("lost changed %s field", name)
		}
		target.Resources[name] = saved
	}
}
