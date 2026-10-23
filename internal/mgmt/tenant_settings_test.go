package mgmt_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestTenantSettingsTransactionAndAudit(t *testing.T) {
	e := newClientsEnv(t) // memory only
	var log bytes.Buffer
	e.h.Log = slog.New(slog.NewJSONHandler(&log, nil))
	ctx := context.Background()
	for _, rs := range []*store.ResourceServer{{TenantID: e.tn.ID, ID: "local", Identifier: "https://local.test"}, {TenantID: e.sys.ID, ID: "foreign", Identifier: "https://foreign.test"}} {
		if err := e.st.ResourceServers().Create(ctx, rs); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*store.Connection{{TenantID: e.tn.ID, ID: "db", Name: "database", Strategy: store.StrategyDatabase}, {TenantID: e.sys.ID, ID: "foreign", Name: "foreign", Strategy: store.StrategyDatabase}} {
		if err := e.st.Connections().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	patch := func(tn *store.Tenant, body any) int {
		rec, _ := e.call(t, tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", body, e.h.UpdateTenantSettings)
		return rec.Code
	}
	if code := patch(e.tn, map[string]any{"default_audience": "https://local.test", "default_directory": "database", "device_flow": map[string]any{"charset": "digits"}, "flags": map[string]any{"enable_sso": false}}); code != 200 {
		t.Fatalf("valid patch %d", code)
	}
	before, _ := e.st.Tenants().Get(ctx, e.tn.ID)
	for _, bad := range []map[string]any{{"default_audience": "https://foreign.test", "friendly_name": "bad"}, {"default_directory": "foreign", "support_email": "bad@example.test"}} {
		if code := patch(e.tn, bad); code != 400 {
			t.Fatalf("foreign reference %d", code)
		}
	}
	after, _ := e.st.Tenants().Get(ctx, e.tn.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("invalid patch mutated tenant")
	}
	if code := patch(e.tn, map[string]any{"device_flow": map[string]any{"mask": "***-***-***"}, "flags": map[string]any{"enable_pipeline2": true}}); code != 200 {
		t.Fatal(code)
	}
	after, _ = e.st.Tenants().Get(ctx, e.tn.ID)
	if after.DeviceFlowCharset != "digits" || after.SettingsExtra["flags"].(map[string]any)["enable_sso"] != false {
		t.Fatal("nested patch lost sibling")
	}
	if !strings.Contains(log.String(), `"actor":"m2m"`) || !strings.Contains(log.String(), `"tenant":"acme"`) || strings.Count(log.String(), "management API: update tenant settings") != 2 {
		t.Fatalf("audit: %s", &log)
	}
	// Even an operator cannot mutate the reserved tenant via this route.
	rec, _ := e.call(t, e.sys, mgmt.Caller{Kind: mgmt.Operator, UserID: "operator"}, "PATCH", "/api/v2/tenants/settings", map[string]any{"default_directory": "database", "friendly_name": "changed"}, e.h.UpdateTenantSettings)
	if rec.Code != 403 {
		t.Fatalf("reserved patch: %d %s", rec.Code, rec.Body)
	}
	systemAfter, _ := e.st.Tenants().Get(ctx, e.sys.ID)
	if !reflect.DeepEqual(systemAfter, e.sys) {
		t.Fatal("system tenant changed")
	}
	// GET must not use the stale tenant object supplied by the resolver.
	rec, out := e.call(t, e.tn, m2mCaller("read:tenant_settings"), "GET", "/api/v2/tenants/settings", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetTenantSettings(w, r, mgmtapi.GetTenantSettingsParams{})
	})
	if rec.Code != 200 || out.(map[string]any)["default_audience"] != "https://local.test" {
		t.Fatalf("stale GET %d %s", rec.Code, rec.Body)
	}
}
