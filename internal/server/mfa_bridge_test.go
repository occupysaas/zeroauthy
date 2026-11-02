package server

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/oauth"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMFABridgeUnavailable(t *testing.T) {
	a := authAPI{}
	cases := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
	}{{"associate", a.MFAAssociate}, {"list", a.MFAListAuthenticators}, {"delete", func(w http.ResponseWriter, r *http.Request) { a.MFADeleteAuthenticator(w, r, "id") }}, {"challenge", a.MFAChallenge}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.call(w, httptest.NewRequest("GET", "/", nil))
			if w.Code != http.StatusNotImplemented || !strings.Contains(w.Body.String(), "mfa_unavailable") {
				t.Fatalf("response: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestMFABridgeDelegates(t *testing.T) {
	st := memory.New()
	tn := &store.Tenant{ID: "tenant", Name: "tenant", Domains: []string{"tenant.example.test"}}
	if err := st.Tenants().Create(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	a := authAPI{oauth: &oauth.Handlers{Store: st, MFA: mfa.NewService(st, nil, nil, nil, nil, nil)}}
	for _, call := range []func(http.ResponseWriter, *http.Request){a.MFAAssociate, a.MFAListAuthenticators, func(w http.ResponseWriter, r *http.Request) { a.MFADeleteAuthenticator(w, r, "id") }, a.MFAChallenge} {
		r := httptest.NewRequest("POST", "https://tenant.example.test/mfa/associate", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: "tenant.example.test"}))
		w := httptest.NewRecorder()
		call(w, r)
		if w.Code != 400 && w.Code != 401 {
			t.Fatalf("MFA adapter did not delegate: %d %s", w.Code, w.Body.String())
		}
	}
}
