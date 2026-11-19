package federation

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPARBegin(t *testing.T) {
	for _, bad := range []bool{false, true} {
		calls := 0
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.Method != "POST" {
				t.Error("PAR method")
			}
			if e := r.ParseForm(); e != nil {
				t.Error(e)
			}
			if r.Form.Get("state") != "state" || r.Form.Get("client_id") != "client" || r.Form.Get("client_assertion") != "fixture-assertion" || r.Form.Has("client_secret") {
				t.Error("incorrect PAR parameters")
			}
			if bad {
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:example:request:123", "expires_in": 60})
		}))
		defer srv.Close()
		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		ps := NewProviders(FixturePolicy(roots), nil)
		cfg := oidcConfig()
		cfg.TokenAuth = "private_key_jwt"
		in := ExchangeInput{Config: cfg, Issuer: srv.URL, Endpoints: Endpoints{TokenURL: srv.URL + "/token", TokenAuthMethod: "private_key_jwt", PAREndpoint: srv.URL + "/par"}, ClientAssertion: func(aud string) (string, error) {
			if aud != srv.URL {
				t.Error("incorrect assertion audience")
			}
			return "fixture-assertion", nil
		}}
		redirect, e := ps.PushAuthorization(context.Background(), srv.URL+"/authorize?state=state&client_id=client&response_type=code", in)
		if (e != nil) != bad {
			t.Fatal(e)
		}
		if !bad {
			u, _ := url.Parse(redirect)
			if len(u.Query()) != 2 || u.Query().Get("request_uri") != "urn:example:request:123" || strings.Contains(redirect, "state=") {
				t.Fatal(redirect)
			}
		}
		if calls != 1 {
			t.Fatal(calls)
		}
	}
}
