package mgmt_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

func TestRetiredResourceContracts(t *testing.T) {
	e := newClientsEnv(t)
	for _, tc := range []struct {
		path string
		fn   http.HandlerFunc
	}{
		{"rules", func(w http.ResponseWriter, r *http.Request) { e.h.GetRules(w, r, mgmtapi.GetRulesParams{}) }},
		{"rules-configs", e.h.GetRulesConfigs},
		{"hooks", func(w http.ResponseWriter, r *http.Request) { e.h.GetHooks(w, r, mgmtapi.GetHooksParams{}) }},
	} {
		rec, _ := e.call(t, e.tn, m2mCaller("read:rules", "read:hooks"), "GET", "/api/v2/"+tc.path, nil, tc.fn)
		if rec.Code != 200 {
			t.Errorf("GET %s = %d %s", tc.path, rec.Code, rec.Body)
		}
	}
	for _, path := range []string{"rules?include_totals=true", "hooks?page=2&per_page=10", "rules-configs"} {
		rec, _ := e.call(t, e.tn, m2mCaller("read:rules", "read:hooks"), "GET", "/api/v2/"+path, nil, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(path, "rules?"):
				e.h.GetRules(w, r, mgmtapi.GetRulesParams{})
			case strings.HasPrefix(path, "hooks"):
				e.h.GetHooks(w, r, mgmtapi.GetHooksParams{})
			default:
				e.h.GetRulesConfigs(w, r)
			}
		})
		if rec.Code != 200 {
			t.Errorf("GET %s = %d %s", path, rec.Code, rec.Body)
		}
	}
}
