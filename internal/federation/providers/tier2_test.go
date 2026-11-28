package providers

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestParseTier2Keys covers the Plan 39d descriptor keys: each valid form
// loads, each malformed one is refused by the strict loader.
func TestParseTier2Keys(t *testing.T) {
	base := func() map[string]any {
		var m map[string]any
		_ = json.Unmarshal([]byte(validDescriptor), &m)
		return m
	}
	valid := map[string]func(map[string]any){
		"get token":      func(m map[string]any) { m["token_method"] = "GET"; m["token_auth"] = AuthQuery },
		"token path":     func(m map[string]any) { m["token_response_path"] = "response" },
		"token accept":   func(m map[string]any) { m["token_accept"] = "application/json" },
		"profile accept": func(m map[string]any) { m["profile_accept"] = "application/vnd.dwolla.v1.hal+json" },
		"redirect param": func(m map[string]any) { m["redirect_param"] = "redirect_url" },
		"fixed params": func(m map[string]any) {
			m["authorize_params"] = map[string]any{"type": "web_server"}
			m["profile_params"] = map[string]any{"fields": "photo_200,screen_name"}
		},
		"query auth":     func(m map[string]any) { m["profile_auth"] = "query:access_token" },
		"scheme auth":    func(m map[string]any) { m["profile_auth"] = "scheme:OAuth" },
		"token template": func(m map[string]any) { m["profile_url"] = "https://api.example.com/users/show.json?uid={token.uid}" },
		"token user id": func(m map[string]any) {
			m["profile"] = map[string]any{"user_id": "token:user_id", "email": "token:email"}
		},
		"retired": func(m map[string]any) {
			m["retired"] = map[string]any{"date": "2024-12-04", "reason": "API shut down", "source": "https://example.com/news"}
		},
		"free scope": func(m map[string]any) { m["free_scope"] = true; m["flags"] = []any{}; m["freeform_scopes"] = false },
		"base url": func(m map[string]any) {
			m["base_url_hosts"] = []any{"start.example.nl", "start.example.be"}
			m["authorization_url"], m["token_url"], m["profile_url"] = "{base_url}/oauth/auth", "{base_url}/oauth/token", "{base_url}/api/me"
		},
		"oauth1": func(m map[string]any) {
			m["protocol"] = "oauth1"
			m["oauth1"] = map[string]any{"request_token_url": "https://www.example.com/oauth", "access_token_url": "https://www.example.com/oauth", "authorization_url": "https://www.example.com/OAuth.action", "empty_secret": true}
			delete(m, "authorization_url")
			delete(m, "token_url")
			delete(m, "profile_url")
			delete(m, "token_auth")
			delete(m, "pkce")
			m["flags"] = []any{}
			m["base_scopes"] = []any{}
			m["freeform_scopes"] = false
			m["profile"] = map[string]any{"user_id": "token:edam_userId"}
		},
	}
	for name, mutate := range valid {
		t.Run("valid "+name, func(t *testing.T) {
			m := base()
			mutate(m)
			b, _ := json.Marshal(m)
			if _, err := Parse(b); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalid := map[string]func(map[string]any){
		"bad method":           func(m map[string]any) { m["token_method"] = "PUT" },
		"query auth with post": func(m map[string]any) { m["token_auth"] = "client_secret_query_typo" },
		"reserved fixed param": func(m map[string]any) { m["authorize_params"] = map[string]any{"client_id": "x"} },
		"reserved token param": func(m map[string]any) { m["token_params"] = map[string]any{"code": "x"} },
		"param with space":     func(m map[string]any) { m["profile_params"] = map[string]any{"a b": "x"} },
		"param value space":    func(m map[string]any) { m["profile_params"] = map[string]any{"a": "x y"} },
		"bad redirect param":   func(m map[string]any) { m["redirect_param"] = "client_id" },
		"bad query auth":       func(m map[string]any) { m["profile_auth"] = "query:" },
		"bad scheme":           func(m map[string]any) { m["profile_auth"] = "scheme:Bad Scheme" },
		"template in host":     func(m map[string]any) { m["profile_url"] = "https://{token.host}/me" },
		"template bad name":    func(m map[string]any) { m["profile_url"] = "https://api.example.com/{token.a/b}" },
		"retired no reason": func(m map[string]any) {
			m["retired"] = map[string]any{"date": "2024-12-04", "source": "https://example.com"}
		},
		"retired bad date": func(m map[string]any) {
			m["retired"] = map[string]any{"date": "December", "reason": "x", "source": "https://example.com"}
		},
		"free scope with flags":  func(m map[string]any) { m["free_scope"] = true },
		"base url without hosts": func(m map[string]any) { m["authorization_url"] = "{base_url}/oauth/auth" },
		"base url bad host":      func(m map[string]any) { m["base_url_hosts"] = []any{"https://x"} },
		"oauth1 without block":   func(m map[string]any) { m["protocol"] = "oauth1" },
		"unknown protocol":       func(m map[string]any) { m["protocol"] = "saml" },
		"bad path index":         func(m map[string]any) { m["profile"] = map[string]any{"user_id": "d.results[x].id"} },
	}
	for name, mutate := range invalid {
		t.Run("invalid "+name, func(t *testing.T) {
			m := base()
			mutate(m)
			b, _ := json.Marshal(m)
			if _, err := Parse(b); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestLookupIndex(t *testing.T) {
	var doc any
	_ = json.Unmarshal([]byte(`{"d":{"results":[{"UserID":"u-1"},{"UserID":"u-2"}]},"response":[{"id":7}]}`), &doc)
	for path, want := range map[string]any{"d.results[0].UserID": "u-1", "d.results[1].UserID": "u-2", "response[0].id": float64(7)} {
		if got, ok := Lookup(doc, path); !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s = %v %v", path, got, ok)
		}
	}
	for _, path := range []string{"d.results[5].UserID", "d.results[-1].UserID", "d[0]", "response[0][0]"} {
		if got, ok := Lookup(doc, path); ok {
			t.Fatalf("%s found %v", path, got)
		}
	}
}
