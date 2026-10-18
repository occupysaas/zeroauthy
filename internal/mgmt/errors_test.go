package mgmt

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return body
}

// D-0039: {statusCode, error, message, errorCode}.
func TestWriteErrorShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusForbidden, "insufficient_scope", "Insufficient scope, expected any of: read:clients")
	if rec.Code != http.StatusForbidden || rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("status %d, content type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := decode(t, rec)
	want := map[string]any{"statusCode": float64(403), "error": "Forbidden",
		"message": "Insufficient scope, expected any of: read:clients", "errorCode": "insufficient_scope"}
	if len(body) != len(want) {
		t.Fatalf("body = %v", body)
	}
	for k, v := range want {
		if body[k] != v {
			t.Errorf("%s = %v, want %v", k, body[k], v)
		}
	}

	rec = httptest.NewRecorder()
	WriteError(rec, http.StatusNotFound, "", "Not Found")
	if body := decode(t, rec); body["error"] != "Not Found" || body["statusCode"] != float64(404) {
		t.Errorf("no code: %v", body)
	}
	if _, ok := decode(t, rec)["errorCode"]; ok {
		t.Error("empty errorCode is written")
	}
}

func TestFail(t *testing.T) {
	rec := httptest.NewRecorder()
	Fail(rec, &Error{Status: http.StatusBadRequest, Code: "invalid_body", Message: "bad"})
	if body := decode(t, rec); rec.Code != 400 || body["errorCode"] != "invalid_body" || body["message"] != "bad" {
		t.Errorf("Error: %d %v", rec.Code, body)
	}
	rec = httptest.NewRecorder()
	Fail(rec, errors.New("database exploded"))
	if body := decode(t, rec); rec.Code != 500 || body["message"] == "database exploded" {
		t.Errorf("other error: %d %v", rec.Code, body)
	}
}
