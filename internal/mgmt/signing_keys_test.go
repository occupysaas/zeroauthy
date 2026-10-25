package mgmt_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
)

func TestSigningKeysAPI(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Keys = keys.NewManager(e.st.SigningKeys(), e.w)
	if err := e.h.Keys.Ensure(t.Context(), e.tn.ID); err != nil {
		t.Fatal(err)
	}
	read := m2mCaller("read:signing_keys")
	rec, _ := e.call(t, e.tn, read, "GET", "/api/v2/keys/signing", nil, func(w http.ResponseWriter, r *http.Request) { e.h.ListSigningKeys(w, r) })
	if rec.Code != 200 {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil || len(rows) != 2 {
		t.Fatalf("list payload: %s err=%v", rec.Body, err)
	}
	for _, row := range rows {
		if _, ok := row["private_key"]; ok {
			t.Fatal("private material leaked")
		}
		if row["cert"] == "" || row["fingerprint"] == "" || row["thumbprint"] == "" || row["pkcs7"] == "" {
			t.Fatalf("certificate metadata missing: %v", row)
		}
	}
	before, _ := e.st.SigningKeys().List(t.Context(), e.tn.ID)
	rot, _ := e.call(t, e.tn, m2mCaller("create:signing_keys"), "POST", "/api/v2/keys/signing/rotate", nil, e.h.RotateSigningKeys)
	if rot.Code != 201 {
		t.Fatalf("rotate: %d %s", rot.Code, rot.Body)
	}
	var rotated map[string]any
	if err := json.Unmarshal(rot.Body.Bytes(), &rotated); err != nil || rotated["kid"] != before[1].KID {
		t.Fatalf("rotate response is not the promoted key: %s", rot.Body)
	}
	revoke, _ := e.call(t, e.tn, m2mCaller("update:signing_keys"), "PUT", "/api/v2/keys/signing/"+before[0].KID+"/revoke", nil, func(w http.ResponseWriter, r *http.Request) { e.h.RevokeSigningKey(w, r, before[0].KID) })
	if revoke.Code != 200 {
		t.Fatalf("revoke previous: %d %s", revoke.Code, revoke.Body)
	}
	var revoked map[string]any
	if err := json.Unmarshal(revoke.Body.Bytes(), &revoked); err != nil || revoked["revoked"] != true {
		t.Fatalf("revoke response: %s", revoke.Body)
	}
	firstTime := revoked["revoked_at"]
	repeated, _ := e.call(t, e.tn, m2mCaller("update:signing_keys"), "PUT", "/api/v2/keys/signing/"+before[0].KID+"/revoke", nil, func(w http.ResponseWriter, r *http.Request) { e.h.RevokeSigningKey(w, r, before[0].KID) })
	var repeatedBody map[string]any
	_ = json.Unmarshal(repeated.Body.Bytes(), &repeatedBody)
	if repeated.Code != 200 || repeatedBody["revoked_at"] != firstTime {
		t.Fatalf("repeated revoke changed response: %d %s", repeated.Code, repeated.Body)
	}
	currentRevoke, _ := e.call(t, e.tn, m2mCaller("update:signing_keys"), "PUT", "/api/v2/keys/signing/"+before[1].KID+"/revoke", nil, func(w http.ResponseWriter, r *http.Request) { e.h.RevokeSigningKey(w, r, before[1].KID) })
	if currentRevoke.Code != 400 {
		t.Fatalf("current revoke: %d %s", currentRevoke.Code, currentRevoke.Body)
	}
	unknown, _ := e.call(t, e.tn, read, "GET", "/api/v2/keys/signing/no-such", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetSigningKey(w, r, "no-such") })
	if unknown.Code != 404 {
		t.Fatalf("unknown key: %d", unknown.Code)
	}
}

func TestSigningKeysReservedTenant(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Keys = keys.NewManager(e.st.SigningKeys(), e.w)
	if err := e.h.Keys.Ensure(t.Context(), e.sys.ID); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.call(t, e.sys, m2mCaller("create:signing_keys"), "POST", "/api/v2/keys/signing/rotate", nil, e.h.RotateSigningKeys)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("reserved tenant rotate: %d %s", rec.Code, rec.Body)
	}
}
