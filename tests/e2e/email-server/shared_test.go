package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func testSink(t *testing.T, handler func(*sink) http.HandlerFunc, path string) (*sink, *httptest.ResponseRecorder) {
	t.Helper()
	s := &sink{}
	w := httptest.NewRecorder()
	handler(s)(w, httptest.NewRequest("GET", path, nil))
	return s, w
}
