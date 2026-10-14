// internal/testutil/contract/contract.go

// Package contract checks HTTP traffic in tests against
// api/authentication.yaml, so handlers cannot drift from the published
// contract.
package contract

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/zeroauthy/zeroauthy/api"
)

// Hosted pages are HTML; the validator only needs to accept the body.
func init() { openapi3filter.RegisterBodyDecoder("text/html", openapi3filter.FileBodyDecoder) }

var (
	loadOnce  sync.Once
	theRouter routers.Router
	loadErr   error
)

func router() (routers.Router, error) {
	loadOnce.Do(func() {
		doc, err := openapi3.NewLoader().LoadFromData(api.AuthenticationYAML)
		if err != nil {
			loadErr = err
			return
		}
		// Match on path only. Test requests use arbitrary hosts and
		// plain HTTP, which the https://{tenant_domain} server entry would
		// otherwise reject (silently skipping validation).
		doc.Servers = nil
		theRouter, loadErr = gorillamux.NewRouter(doc)
	})
	return theRouter, loadErr
}

// Wrap validates every request and response passing through h.
func Wrap(t testing.TB, h http.Handler) http.Handler { return wrap(t, h, true) }

// WrapResponses validates only responses. Use it in tests that send
// deliberately invalid requests.
func WrapResponses(t testing.TB, h http.Handler) http.Handler { return wrap(t, h, false) }

func wrap(t testing.TB, h http.Handler, checkRequest bool) http.Handler {
	t.Helper()
	rt, err := router()
	if err != nil {
		t.Fatalf("contract: load spec: %v", err)
	}
	opts := &openapi3filter.Options{
		AuthenticationFunc:    openapi3filter.NoopAuthenticationFunc,
		IncludeResponseStatus: true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params, err := rt.FindRoute(r)
		if err != nil {
			t.Errorf("contract: %s %s is not described in api/authentication.yaml: %v", r.Method, r.URL.Path, err)
			h.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		in := &openapi3filter.RequestValidationInput{Request: r, PathParams: params, Route: route, Options: opts}
		if checkRequest {
			if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
				t.Errorf("contract: request %s %s violates spec: %v", r.Method, r.URL.Path, err)
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)

		out := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: in,
			Status:                 rec.Code,
			Header:                 rec.Header(),
			Body:                   io.NopCloser(bytes.NewReader(rec.Body.Bytes())),
			Options:                opts,
		}
		if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
			t.Errorf("contract: response %d to %s %s violates spec: %v", rec.Code, r.Method, r.URL.Path, err)
		}

		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}
