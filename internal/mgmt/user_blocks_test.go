package mgmt_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestUserBlocksIsolation(t *testing.T) {
	e := newClientsEnv(t)
	ctx := context.Background()
	e.h.Now = func() time.Time { return now }
	tenant, _ := e.st.Tenants().Get(ctx, e.tn.ID)
	tenant.ProtectionSettings = protectionrules.Defaults()
	tenant.ProtectionSettings.BruteForce.MaxAttempts = 1
	tenant.ProtectionSettingsInitialized = true
	if err := e.st.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	other := &store.Tenant{ID: "other", Name: "other"}
	if err := e.st.Tenants().Create(ctx, other); err != nil {
		t.Fatal(err)
	}
	for _, tid := range []string{e.tn.ID, other.ID} {
		for _, c := range []*store.Connection{{TenantID: tid, ID: "db", Name: "Database", Strategy: store.StrategyDatabase, BruteForceProtection: true}, {TenantID: tid, ID: "linked", Name: "Linked", Strategy: store.StrategyDatabase, BruteForceProtection: true}} {
			if err := e.st.Connections().Create(ctx, c); err != nil {
				t.Fatal(err)
			}
		}
	}
	u := &store.User{TenantID: e.tn.ID, UserID: "auth0|one", Email: "same@example.test", Username: "alias", Blocked: true, Identities: []store.Identity{{Connection: "Database", Provider: store.StrategyDatabase, UserID: "one"}, {Connection: "Linked", Provider: store.StrategyDatabase, UserID: "two", ProfileData: map[string]any{"email": "linked@example.test", "username": "linked-alias"}}}}
	if err := e.st.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	block := func(key store.ProtectionKey, algorithm string) {
		a, err := e.st.Protection().Reserve(ctx, []store.ProtectionLimit{{Key: key, Algorithm: algorithm, Capacity: 1, Lockout: time.Hour, Window: time.Hour, Refill: time.Hour}}, now)
		if err != nil || !a.Allowed {
			t.Fatal("reserve", a, err)
		}
		if err := e.st.Protection().Complete(ctx, a.Receipt, "failure", now); err != nil {
			t.Fatal(err)
		}
	}
	key := protection.LoginKey(e.tn.ID, "db", u.Email, "192.0.2.1", "count_per_identifier_and_ip")
	block(key, "brute-force")
	// Provider IDs are not login aliases: another identity may use that text.
	unrelated := protection.LoginKey(e.tn.ID, "db", "one", "192.0.2.9", "count_per_identifier_and_ip")
	block(unrelated, "brute-force")
	foreign := key
	foreign.TenantID = other.ID
	block(foreign, "brute-force")
	linked := protection.LoginKey(e.tn.ID, "linked", "linked@example.test", "192.0.2.2", "count_per_identifier_and_ip")
	block(linked, "brute-force")
	ip := store.ProtectionKey{TenantID: e.tn.ID, Kind: store.ProtectionSuspiciousIPLogin, IP: "192.0.2.1"}
	block(ip, "token-bucket")
	reset := store.ProtectionKey{TenantID: e.tn.ID, Kind: store.ProtectionResetMail, Identifier: u.Email}
	block(reset, "fixed-window")
	call := func(method, id, query string) (int, map[string]any) {
		rec, out := e.call(t, e.tn, m2mCaller("read:users", "update:users"), method, "/api/v2/user-blocks"+query, nil, func(w http.ResponseWriter, r *http.Request) { e.h.UserBlocks(w, r, id) })
		m, _ := out.(map[string]any)
		return rec.Code, m
	}
	if status, body := call("GET", u.UserID, ""); status != 200 || len(body["blocked_for"].([]any)) != 2 {
		t.Fatalf("linked union: %d %v", status, body)
	}
	if status, body := call("GET", "", "?identifier=alias"); status != 200 || len(body["blocked_for"].([]any)) != 1 {
		t.Fatalf("alias: %d %v", status, body)
	}
	connection, err := e.st.Connections().Get(ctx, e.tn.ID, "linked")
	if err != nil {
		t.Fatal(err)
	}
	connection.BruteForceProtection = false
	if err := e.st.Connections().Update(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if status, body := call("GET", u.UserID, "?consider_brute_force_enablement=true"); status != 200 || len(body["blocked_for"].([]any)) != 1 {
		t.Fatalf("connection enablement: %d %v", status, body)
	}
	if status, body := call("GET", u.UserID, ""); status != 200 || len(body["blocked_for"].([]any)) != 2 {
		t.Fatalf("default must retain disabled connection blocks: %d %v", status, body)
	}
	// Enablement filters visibility without destroying saved blocks.
	tenant, _ = e.st.Tenants().Get(ctx, e.tn.ID)
	tenant.ProtectionSettings.BruteForce.Enabled = false
	if err := e.st.Tenants().Update(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if status, body := call("GET", u.UserID, "?consider_brute_force_enablement=true"); status != 200 || len(body["blocked_for"].([]any)) != 0 {
		t.Fatalf("enablement: %d %v", status, body)
	}
	if status := func() int { s, _ := call("DELETE", u.UserID, ""); return s }(); status != 204 {
		t.Fatal(status)
	}
	saved, _ := e.st.Users().Get(ctx, e.tn.ID, u.UserID)
	if !saved.Blocked {
		t.Fatal("administrative block cleared")
	}
	for _, k := range []store.ProtectionKey{foreign, ip, reset, unrelated} {
		bs, err := e.st.Protection().Blocks(ctx, k.TenantID, store.ProtectionFilter{Kind: k.Kind, Identifier: k.Identifier, IP: k.IP}, now)
		if err != nil || len(bs) != 1 {
			t.Fatalf("unrelated state cleared: %#v %v %v", k, bs, err)
		}
	}
	bs, _ := e.st.Protection().Blocks(ctx, e.tn.ID, store.ProtectionFilter{Kind: store.ProtectionBruteForce}, now)
	if len(bs) != 1 || bs[0].Key != unrelated {
		t.Fatal("linked blocks retained", bs)
	}
	rec, _ := e.call(t, e.tn, m2mCaller("read:anomaly_blocks"), "GET", "/", nil, func(w http.ResponseWriter, r *http.Request) { e.h.IPBlock(w, r, "::ffff:192.0.2.1") })
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Fatalf("IP canonical/body: %d %s", rec.Code, rec.Body)
	}
	rec, _ = e.call(t, e.tn, m2mCaller("delete:anomaly_blocks"), "DELETE", "/", nil, func(w http.ResponseWriter, r *http.Request) { e.h.IPBlock(w, r, "192.0.2.1") })
	if rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	for _, k := range []store.ProtectionKey{foreign, reset, unrelated} {
		bs, err := e.st.Protection().Blocks(ctx, k.TenantID, store.ProtectionFilter{Kind: k.Kind, Identifier: k.Identifier, IP: k.IP}, now)
		if err != nil || len(bs) != 1 {
			t.Fatal("IP unblock cleared unrelated state", k, bs, err)
		}
	}
}
