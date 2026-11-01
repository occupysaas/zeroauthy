package server

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestSystemLogStreamStatus(t *testing.T) {
	h, st := newMgmtEnv(t)
	ctx := t.Context()
	acme, _ := st.Tenants().GetByName(ctx, "acme")
	sys := mustSystemID(t, st)
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if err := st.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: acme.ID, ID: "stream-one", Type: "http", Status: "suspended", Sink: map[string]any{"httpEndpoint": "https://private-endpoint.example.test"}, SealedSecrets: []byte("PRIVATE_SEALED"), LastSuccessAt: at, NextAt: at.Add(time.Minute), Failures: 3, LastErrorClass: "http_5xx", LeaseOwner: "PRIVATE_LEASE"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: sys, ID: "other-tenant", Type: "http", Status: "paused"}); err != nil {
		t.Fatal(err)
	}
	_, uid := tenantOperatorToken(t, st, "stream-health@example.test", []string{"*"})
	setGrants := func(names ...string) {
		t.Helper()
		if err := st.Operators().Upsert(ctx, &store.Operator{TenantID: sys, UserID: uid, Tenants: names}); err != nil {
			t.Fatal(err)
		}
	}
	setGrants("acme")
	token := mintTargetOperator(t, st, uid, []string{"acme"})
	endpoint := "https://" + mgmtSystemHost + "/api/system/tenants/acme/log-streams/status"
	w, _ := sendRaw(h, "GET", endpoint, token, nil)
	expected := []map[string]any{{"id": "stream-one", "status": "suspended", "last_success_at": "2026-10-30T12:00:00Z", "next_at": "2026-10-30T12:01:00Z", "failures": float64(3), "last_error_class": "http_5xx"}}
	var got []map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, expected) {
		t.Fatalf("health=%d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		url, token string
		want       int
	}{
		{endpoint, "", 401},
		{endpoint, mintTargetOperator(t, st, uid, []string{"system"}), 403},
		{"https://acme.example.test/api/system/tenants/acme/log-streams/status", token, 404},
		{"https://" + mgmtSystemHost + "/api/system/tenants/missing/log-streams/status", token, 404},
	} {
		w, _ := sendRaw(h, "GET", tc.url, tc.token, nil)
		if w.Code != tc.want {
			t.Fatalf("GET %s=%d %s", tc.url, w.Code, w.Body)
		}
	}
	setGrants("system")
	if w, _ := sendRaw(h, "GET", endpoint, token, nil); w.Code != 403 {
		t.Fatalf("revoked live target grant=%d %s", w.Code, w.Body)
	}
	setGrants("acme")
	m2m := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	if w, _ := sendRaw(h, "GET", endpoint, m2m, nil); w.Code == 200 {
		t.Fatalf("M2M accepted: %s", w.Body)
	}
}

func TestSystemLogStreamStatusUnavailable(t *testing.T) {
	h, st := newMgmtEnvWith(t, func(d *Deps) { d.Store = serverStreamsUnavailable{d.Store} })
	token, _ := operatorToken(t, st, "health-unavailable@example.test")
	w, _ := sendRaw(h, "GET", "https://"+mgmtSystemHost+"/api/system/tenants/acme/log-streams/status", token, nil)
	if w.Code != 501 || !strings.Contains(w.Body.String(), "logs_unavailable") {
		t.Fatalf("capability=%d %s", w.Code, w.Body)
	}
}
