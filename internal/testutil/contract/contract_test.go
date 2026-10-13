// internal/testutil/contract/contract_test.go
package contract

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder captures Errorf calls instead of failing the real test.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func respond(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func do(h http.Handler, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const form = "application/x-www-form-urlencoded"

func TestValidExchangePasses(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(200, `{"access_token":"x","token_type":"Bearer","expires_in":60}`))
	rec := do(h, "POST", "https://acme.test/oauth/token", form, "grant_type=client_credentials")
	if len(r.errs) != 0 {
		t.Fatalf("unexpected violations: %v", r.errs)
	}
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token":"x"`) {
		t.Fatalf("response not passed through: %d %s", rec.Code, rec.Body)
	}
}

func TestBadResponseIsReported(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(200, `{"token_type":"Bearer","expires_in":60}`))
	do(h, "POST", "https://acme.test/oauth/token", form, "grant_type=client_credentials")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "access_token") {
		t.Fatalf("violations = %v", r.errs)
	}
}

func TestUndeclaredStatusIsReported(t *testing.T) {
	r := &recorder{TB: t}
	h := Wrap(r, respond(418, `{"error":"teapot","error_description":"x"}`))
	do(h, "GET", "https://acme.test/.well-known/jwks.json", "", "")
	// 418 falls under "default", which is declared, so it passes. A
	// response whose body doesn't match must still fail:
	h = Wrap(r, respond(418, `{"oops":true}`))
	do(h, "GET", "https://acme.test/.well-known/jwks.json", "", "")
	if len(r.errs) != 1 {
		t.Fatalf("violations = %v", r.errs)
	}
}

func TestBadRequestReportedOnlyByWrap(t *testing.T) {
	ok := respond(400, `{"error":"invalid_request","error_description":"grant_type is required"}`)

	r := &recorder{TB: t}
	do(Wrap(r, ok), "POST", "https://acme.test/oauth/token", form, "audience=x")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "grant_type") {
		t.Fatalf("Wrap violations = %v", r.errs)
	}

	r = &recorder{TB: t}
	do(WrapResponses(r, ok), "POST", "https://acme.test/oauth/token", form, "audience=x")
	if len(r.errs) != 0 {
		t.Fatalf("WrapResponses violations = %v", r.errs)
	}
}

func TestUnknownPathIsReported(t *testing.T) {
	r := &recorder{TB: t}
	do(Wrap(r, respond(200, `{}`)), "GET", "https://acme.test/not-in-spec", "", "")
	if len(r.errs) != 1 || !strings.Contains(r.errs[0], "not described") {
		t.Fatalf("violations = %v", r.errs)
	}
}
