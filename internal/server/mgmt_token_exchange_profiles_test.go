package server

import (
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type noProfileStore struct{ store.Store }

func (noProfileStore) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

// TestTokenExchangeProfileScopes: each profile route needs exactly its own
// scope. A token holding every other profile scope is refused (403), so a
// route wired to a sibling's scope fails here; the route's own scope passes
// the scope check (the handler then answers 501 for the store without
// profiles, which keeps the test from needing a tenant).
func TestTokenExchangeProfileScopes(t *testing.T) {
	h := mgmtapi.Handler(mgmtAPI{h: &mgmt.Handlers{Store: noProfileStore{memory.New()}}})
	all := []string{"read:token_exchange_profiles", "create:token_exchange_profiles", "update:token_exchange_profiles", "delete:token_exchange_profiles"}
	for _, item := range []struct{ method, path, scope string }{
		{"GET", "", "read:token_exchange_profiles"},
		{"POST", "", "create:token_exchange_profiles"},
		{"GET", "/tep_0000000000000000000001", "read:token_exchange_profiles"},
		{"PATCH", "/tep_0000000000000000000001", "update:token_exchange_profiles"},
		{"DELETE", "/tep_0000000000000000000001", "delete:token_exchange_profiles"},
	} {
		target := "/api/v2/token-exchange-profiles" + item.path
		do := func(scopes []string) int {
			r := httptest.NewRequest(item.method, target, nil)
			if scopes != nil {
				r = r.WithContext(mgmt.WithCaller(r.Context(), mgmt.Caller{Kind: mgmt.M2M, Scopes: scopes}))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
		if got := do(nil); got != 401 {
			t.Errorf("%s %s without a token = %d, want 401", item.method, target, got)
		}
		others := slices.DeleteFunc(slices.Clone(all), func(s string) bool { return s == item.scope })
		if got := do(others); got != 403 {
			t.Errorf("%s %s with the other profile scopes = %d, want 403", item.method, target, got)
		}
		if got := do([]string{item.scope}); got == 401 || got == 403 {
			t.Errorf("%s %s with its own scope = %d, want past the scope check", item.method, target, got)
		}
	}
}
