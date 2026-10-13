// internal/oauth/clientauth_test.go
package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func authRequest(t *testing.T, body url.Values, basicID, basicSecret string) (*http.Request, url.Values) {
	t.Helper()
	req := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(url.QueryEscape(basicID), url.QueryEscape(basicSecret))
	}
	form, oerr := parseTokenRequest(httptest.NewRecorder(), req)
	if oerr != nil {
		t.Fatal(oerr)
	}
	return req, form
}

func TestAuthenticateClient(t *testing.T) {
	f := newFixture(t)
	acme := f.tenantID(t, "acme")
	globex := f.tenantID(t, "globex")

	cases := []struct {
		name          string
		tenantID      string
		body          url.Values
		basicID       string
		basicSecret   string
		wantClient    string
		wantCode      string
		wantStatus    int
		wantChallenge bool
	}{
		{name: "post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantClient: "m2m"},
		// Review focus 3: reserved characters in Basic credentials.
		{name: "basic with reserved chars", tenantID: acme, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "basic plus matching body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantClient: "m2m-basic"},
		{name: "public client", tenantID: acme, body: url.Values{"client_id": {"spa"}}, wantClient: "spa"},
		{name: "wrong secret post", tenantID: acme, body: url.Values{"client_id": {"m2m"}, "client_secret": {"nope"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "wrong secret basic", tenantID: acme, basicID: "m2m-basic", basicSecret: "nope", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "unknown client", tenantID: acme, body: url.Values{"client_id": {"ghost"}, "client_secret": {"x"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "no client id", tenantID: acme, body: url.Values{}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch post for basic client", tenantID: acme, body: url.Values{"client_id": {"m2m-basic"}, "client_secret": {"p@ss:w+rd"}}, wantCode: "invalid_client", wantStatus: 401},
		{name: "method mismatch basic for post client", tenantID: acme, basicID: "m2m", basicSecret: "m2m-secret", wantCode: "invalid_client", wantStatus: 401, wantChallenge: true},
		{name: "confidential client without secret", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, wantCode: "invalid_client", wantStatus: 401},
		// Review focus 2: two methods at once.
		{name: "basic and body secret", tenantID: acme, body: url.Values{"client_secret": {"p@ss:w+rd"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		{name: "basic and different body client_id", tenantID: acme, body: url.Values{"client_id": {"m2m"}}, basicID: "m2m-basic", basicSecret: "p@ss:w+rd", wantCode: "invalid_request", wantStatus: 400},
		// Review focus 5: tenant isolation.
		{name: "client from other tenant", tenantID: globex, body: url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, wantCode: "invalid_client", wantStatus: 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, form := authRequest(t, tc.body, tc.basicID, tc.basicSecret)
			c, oerr := f.h.authenticateClient(context.Background(), req, form, tc.tenantID)
			if tc.wantClient != "" {
				if oerr != nil {
					t.Fatalf("unexpected error %+v", oerr)
				}
				if c.ClientID != tc.wantClient {
					t.Fatalf("client = %s, want %s", c.ClientID, tc.wantClient)
				}
				return
			}
			if oerr == nil || oerr.Code != tc.wantCode || oerr.Status != tc.wantStatus || oerr.basicChallenge != tc.wantChallenge {
				t.Fatalf("err = %+v, want %s/%d challenge=%v", oerr, tc.wantCode, tc.wantStatus, tc.wantChallenge)
			}
		})
	}
}

func TestExpiredSecretRejected(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acme := f.tenantID(t, "acme")
	c, _ := f.st.Clients().Get(ctx, acme, "m2m")
	old, _ := secrets.Hash("old-secret")
	expired := fixedNow().Add(-time.Minute)
	c.Secrets = append([]store.ClientSecret{{Hash: old, CreatedAt: fixedNow().Add(-time.Hour), ExpiresAt: &expired}}, c.Secrets...)
	if err := f.st.Clients().Update(ctx, c); err != nil {
		t.Fatal(err)
	}

	req, form := authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"old-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr == nil || oerr.Code != "invalid_client" {
		t.Fatalf("expired secret accepted: %+v", oerr)
	}
	req, form = authRequest(t, url.Values{"client_id": {"m2m"}, "client_secret": {"m2m-secret"}}, "", "")
	if _, oerr := f.h.authenticateClient(ctx, req, form, acme); oerr != nil {
		t.Fatalf("current secret rejected: %+v", oerr)
	}
}

func TestWriteErrorHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	writeError(rec, invalidClient("client authentication failed", true))
	if rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("headers = %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("body = %s", rec.Body)
	}
}
