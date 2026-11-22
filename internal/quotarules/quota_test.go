package quotarules

import (
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
)

func TestQuotaValidation(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`null`, true}, {`{}`, false}, {`{"client_credentials":{}}`, false}, {`{"client_credentials":{"per_hour":0}}`, false}, {`{"client_credentials":{"per_day":2147483648}}`, false}, {`{"client_credentials":{"per_hour":1.5}}`, false}, {`{"client_credentials":{"per_hour":"1"}}`, false}, {`{"client_credentials":{"enforce":null}}`, false}, {`{"client_credentials":{"per_day":1,"unknown":1}}`, false}, {`{"other":{"per_hour":1}}`, false}, {`{"client_credentials":{"per_hour":10}}`, true}, {`{"client_credentials":{"enforce":false,"per_day":20}}`, true}, {`{"client_credentials":{"enforce":true}}`, true},
	} {
		t.Run(tc.body, func(t *testing.T) {
			var v any
			if err := json.Unmarshal([]byte(tc.body), &v); err != nil {
				t.Fatal(err)
			}
			q, err := ParseTokenQuota(v, "token_quota")
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.body == `{"client_credentials":{"per_hour":10}}` && (q == nil || !q.Enforce || q.PerHour != 10) {
				t.Fatalf("missing default/limit: %#v", q)
			}
		})
	}
}

func TestQuotaPatchIsolation(t *testing.T) {
	current := &store.DefaultTokenQuota{Clients: &store.TokenQuota{Enforce: true, PerHour: 3}, Organizations: &store.TokenQuota{Enforce: true, PerDay: 5}}
	next, err := PatchDefaultTokenQuota(current, map[string]any{"clients": map[string]any{"client_credentials": map[string]any{"enforce": false}}})
	if err != nil {
		t.Fatal(err)
	}
	next.Clients.PerHour = 9
	next.Organizations.PerDay = 8
	if current.Clients.PerHour != 3 || current.Organizations.PerDay != 5 || !current.Clients.Enforce {
		t.Fatal("patch shares current configuration")
	}
}
