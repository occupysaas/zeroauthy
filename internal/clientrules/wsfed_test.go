package clientrules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestParseAddonsWSFed(t *testing.T) {
	a, err := ParseAddons(json.RawMessage(`{"wsfed":{}}`))
	if err != nil || a == nil || a.WSFed == nil || a.SAMLP != nil {
		t.Fatalf("enabled: %+v %v", a, err)
	}
	a, err = ParseAddons(json.RawMessage(`{"wsfed":{"note":"kept"},"samlp":{}}`))
	if err != nil || a.WSFed == nil || a.SAMLP == nil {
		t.Fatalf("both add-ons: %+v %v", a, err)
	}
	pub, _ := json.Marshal(PublicAddons(a))
	if !strings.Contains(string(pub), `"wsfed":{"note":"kept"}`) || !strings.Contains(string(pub), `"samlp":{`) {
		t.Fatalf("public form %s", pub)
	}
	pub, _ = json.Marshal(PublicAddons(mustAddons(t, `{"wsfed":{}}`)))
	if string(pub) != `{"wsfed":{}}` {
		t.Fatalf("wsfed only public form %s", pub)
	}
	for _, empty := range []string{`{"wsfed":null}`, `{"wsfed":null,"samlp":null}`} {
		if a, err := ParseAddons(json.RawMessage(empty)); err != nil || a != nil {
			t.Fatalf("%s: %+v %v", empty, a, err)
		}
	}
	for name, bad := range map[string]string{
		"string":   `{"wsfed":"yes"}`,
		"array":    `{"wsfed":[]}`,
		"too big":  `{"wsfed":{"x":"` + strings.Repeat("a", 4096) + `"}}`,
		"other":    `{"wsfed":{},"box":{}}`,
		"bad json": `{"wsfed":{]}`,
	} {
		if _, err := ParseAddons(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func mustAddons(t *testing.T, raw string) *store.ClientAddons {
	t.Helper()
	a, err := ParseAddons(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestParseClientAliases(t *testing.T) {
	got, err := ParseClientAliases(json.RawMessage(`["urn:sharepoint:portal","https://rp.example.test/"]`))
	if err != nil || strings.Join(got, ",") != "urn:sharepoint:portal,https://rp.example.test/" {
		t.Fatalf("got %v %v", got, err)
	}
	for _, empty := range []string{`null`, `[]`} {
		if got, err := ParseClientAliases(json.RawMessage(empty)); err != nil || len(got) != 0 {
			t.Fatalf("%s: %v %v", empty, got, err)
		}
	}
	many := make([]string, 101)
	for i := range many {
		many[i] = `"a` + strings.Repeat("b", i) + `"`
	}
	for name, bad := range map[string]string{
		"empty alias": `[""]`,
		"not string":  `[1]`,
		"object":      `{"a":1}`,
		"too long":    `["` + strings.Repeat("a", 1025) + `"]`,
		"too many":    `[` + strings.Join(many, ",") + `]`,
		"duplicate":   `["urn:a","urn:a"]`,
		"control":     `["urn:a\n"]`,
	} {
		if _, err := ParseClientAliases(json.RawMessage(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
