package providers

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDescriptorsLoad(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("no descriptors embedded")
	}
	seen := map[string]bool{}
	for _, d := range all {
		if seen[d.Strategy] {
			t.Fatalf("duplicate strategy %s", d.Strategy)
		}
		seen[d.Strategy] = true
		if got, ok := Get(d.Strategy); !ok || got.Strategy != d.Strategy {
			t.Fatalf("Get(%s)", d.Strategy)
		}
		if err := d.validate(); err != nil {
			t.Fatalf("%s: %v", d.Strategy, err)
		}
	}
	if _, ok := Get("github"); ok {
		t.Fatal("github must stay on its Plan 39c adapter")
	}
	if _, ok := Get("nope"); ok {
		t.Fatal("unknown strategy found")
	}
}

func TestGetReturnsCopy(t *testing.T) {
	d, _ := Get("amazon")
	d.BaseScopes[0] = "mutated"
	d2, _ := Get("amazon")
	if d2.BaseScopes[0] == "mutated" {
		t.Fatal("Get returned shared state")
	}
}

const validDescriptor = `{"strategy":"example","display_name":"Example","source":["https://example.com/docs"],
"authorization_url":"https://example.com/authorize","token_url":"https://example.com/token","profile_url":"https://api.example.com/me",
"token_auth":"client_secret_post","pkce":"S256","base_scopes":["profile"],"flags":[{"option":"email","scopes":["email"]}],
"freeform_scopes":true,"profile":{"user_id":"id","email":"email"},"email_verified":{"rule":"never"}}`

func TestParseStrict(t *testing.T) {
	if _, err := Parse([]byte(validDescriptor)); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown field":      func(m map[string]any) { m["surprise"] = true },
		"http endpoint":      func(m map[string]any) { m["token_url"] = "http://example.com/token" },
		"endpoint userinfo":  func(m map[string]any) { m["token_url"] = "https://u:p@example.com/token" },
		"bad token auth":     func(m map[string]any) { m["token_auth"] = "private_key_jwt" },
		"bad pkce":           func(m map[string]any) { m["pkce"] = "plain" },
		"no user id":         func(m map[string]any) { m["profile"] = map[string]any{"email": "email"} },
		"bad email rule":     func(m map[string]any) { m["email_verified"] = map[string]any{"rule": "sometimes"} },
		"field rule no path": func(m map[string]any) { m["email_verified"] = map[string]any{"rule": "field"} },
		"always no email": func(m map[string]any) {
			m["profile"] = map[string]any{"user_id": "id"}
			m["email_verified"] = map[string]any{"rule": "always"}
		},
		"no source": func(m map[string]any) { m["source"] = []any{} },
		"dup flag": func(m map[string]any) {
			m["flags"] = []any{map[string]any{"option": "a", "scopes": []any{"x"}}, map[string]any{"option": "a", "scopes": []any{"y"}}}
		},
		"flag without scopes": func(m map[string]any) { m["flags"] = []any{map[string]any{"option": "a"}} },
		"scope with space":    func(m map[string]any) { m["base_scopes"] = []any{"a b"} },
		"bad method":          func(m map[string]any) { m["profile_method"] = "DELETE" },
		"bad profile auth":    func(m map[string]any) { m["profile_auth"] = "cookie" },
		"unknown hook":        func(m map[string]any) { m["hook"] = "mystery" },
		"bad strategy":        func(m map[string]any) { m["strategy"] = "Has Space" },
	} {
		t.Run(name, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal([]byte(validDescriptor), &m)
			mutate(m)
			b, _ := json.Marshal(m)
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLookup(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"id":"1","data":{"name":"N","n":5},
	"emails":[{"value":"a@x","primary":false},{"value":"b@x","primary":true,"confirmed":true}],
	"empty":[]}`), &doc)
	for path, want := range map[string]any{
		"id":                         "1",
		"data.name":                  "N",
		"data.n":                     float64(5),
		"emails[?primary].value":     "b@x",
		"emails[?primary].confirmed": true,
	} {
		got, ok := Lookup(doc, path)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s = %v %v, want %v", path, got, ok, want)
		}
	}
	for _, path := range []string{"", "missing", "data.missing", "id.x", "empty[?primary].value", "emails[?nope].value", "emails.value", "emails[?primary"} {
		if got, ok := Lookup(doc, path); ok {
			t.Fatalf("%s found %v", path, got)
		}
	}
}

func TestFlagScopes(t *testing.T) {
	d, _ := Parse([]byte(strings.Replace(validDescriptor, `"flags":[{"option":"email","scopes":["email"]}]`,
		`"flags":[{"option":"email","scopes":["email"]},{"option":"pub","scopes":["profile","pub"],"default":true}]`, 1)))
	got := d.EffectiveScopes(func(opt string, def bool) bool { return def || opt == "email" }, []string{"extra", "email"})
	if want := []string{"profile", "email", "pub", "extra"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes %v, want %v", got, want)
	}
}
