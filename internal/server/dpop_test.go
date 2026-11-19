package server

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDPoPCORS(t *testing.T) {
	st := memory.New()
	tn := &store.Tenant{ID: "tenant", Name: "tenant"}
	if e := st.Clients().Create(t.Context(), &store.Client{TenantID: tn.ID, ClientID: "app", WebOrigins: []string{"https://app.example"}}); e != nil {
		t.Fatal(e)
	}
	h := cors(st)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("DPoP-Nonce", "nonce") }))
	for _, method := range []string{"POST", "OPTIONS"} {
		r := httptest.NewRequest(method, "https://tenant.example/oauth/token", nil)
		r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: "tenant.example"}))
		r.Header.Set("Origin", "https://app.example")
		r.Header.Set("Access-Control-Request-Headers", "DPoP, Content-Type")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Header().Get("Access-Control-Expose-Headers") != "DPoP-Nonce" {
			t.Fatal("nonce not exposed")
		}
		if method == "OPTIONS" && !strings.Contains(rec.Header().Get("Access-Control-Allow-Headers"), "DPoP") {
			t.Fatal("proof header not allowed")
		}
	}
}
