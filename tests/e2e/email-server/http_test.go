package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCapturedMessagesHTTP(t *testing.T) {
	s := &sink{}
	s.add("From: sender@example.test\r\nTo: user@example.test\r\nSubject: captured\r\n")
	get := httptest.NewRecorder()
	s.list(get, httptest.NewRequest(http.MethodGet, "/messages", nil))
	var messages []string
	if err := json.Unmarshal(get.Body.Bytes(), &messages); err != nil || len(messages) != 1 || messages[0] == "" {
		t.Fatalf("message capture response = %q, %v", get.Body.String(), err)
	}
	clear := httptest.NewRecorder()
	s.clear(clear, httptest.NewRequest(http.MethodPost, "/clear", nil))
	if clear.Code != http.StatusNoContent {
		t.Fatalf("clear status = %d", clear.Code)
	}
	get = httptest.NewRecorder()
	s.list(get, httptest.NewRequest(http.MethodGet, "/messages", nil))
	if got := get.Body.String(); got != "[]\n" {
		t.Fatalf("messages after clear = %s", got)
	}
}
