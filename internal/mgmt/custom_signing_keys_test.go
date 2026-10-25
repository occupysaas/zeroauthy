package mgmt_test

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestCustomSigningKeysAPI(t *testing.T) {
	e := newClientsEnv(t)
	var logs bytes.Buffer
	e.h.Log = slog.New(slog.NewTextHandler(&logs, nil))
	get := m2mCaller("read:signing_keys")
	put := m2mCaller("update:signing_keys")
	absent, _ := e.call(t, e.tn, get, "GET", "/api/v2/keys/custom-signing", nil, e.h.GetCustomSigningKeys)
	if absent.Code != 404 {
		t.Fatalf("absent set: %d", absent.Code)
	}
	body := `{"keys":[{"kty":"RSA","kid":"custom1","use":"sig","alg":"RS256","n":"AQAB","e":"Aw"}]}`
	rec, _ := e.call(t, e.tn, put, "PUT", "/api/v2/keys/custom-signing", body, e.h.PutCustomSigningKeys)
	if rec.Code != 200 {
		t.Fatalf("put: %d %s", rec.Code, rec.Body)
	}
	invalid, _ := e.call(t, e.tn, put, "PUT", "/api/v2/keys/custom-signing", `{"keys":[{"kty":"oct","kid":"x","k":"private-sentinel"}]}`, e.h.PutCustomSigningKeys)
	if invalid.Code != 400 {
		t.Fatalf("invalid set: %d", invalid.Code)
	}
	if strings.Contains(logs.String(), "private-sentinel") {
		t.Fatalf("raw key material was logged: %s", logs.String())
	}
	getRec, _ := e.call(t, e.tn, get, "GET", "/api/v2/keys/custom-signing", nil, e.h.GetCustomSigningKeys)
	if getRec.Code != 200 || !strings.Contains(getRec.Body.String(), "custom1") {
		t.Fatalf("replacement lost: %d", getRec.Code)
	}
	del, _ := e.call(t, e.tn, put, "DELETE", "/api/v2/keys/custom-signing", nil, e.h.DeleteCustomSigningKeys)
	if del.Code != 204 {
		t.Fatalf("delete: %d %s", del.Code, del.Body)
	}
	if !strings.Contains(logs.String(), "tenant=acme") || !strings.Contains(logs.String(), "actor=m2m") || !strings.Contains(logs.String(), "custom1") {
		t.Fatalf("successful writes missing audit metadata: %s", logs.String())
	}
}
