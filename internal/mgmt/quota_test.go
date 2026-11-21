package mgmt_test

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"log/slog"
	"net/http"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

func TestQuotaConfiguration(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Log = slog.New(slog.DiscardHandler)
	quota := map[string]any{"client_credentials": map[string]any{"per_hour": 10}}
	rec, out := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", map[string]any{"name": "quota", "app_type": "non_interactive", "token_quota": quota}, e.h.CreateClient)
	if rec.Code != 201 {
		t.Fatalf("create client status %d", rec.Code)
	}
	view := out.(map[string]any)
	id := view["client_id"].(string)
	if view["token_quota"].(map[string]any)["client_credentials"].(map[string]any)["enforce"] != true {
		t.Fatal("enforce default lost")
	}
	rec, _ = e.call(t, e.tn, m2mCaller(allClientScopes...), "PATCH", "/api/v2/clients/"+id, map[string]any{"token_quota": nil}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) })
	if rec.Code != 200 {
		t.Fatal("clear client", rec.Code)
	}
	c, err := e.st.Clients().Get(t.Context(), e.tn.ID, id)
	if err != nil || c.TokenQuota != nil {
		t.Fatal("client quota not cleared")
	}
	rec, out = e.call(t, e.tn, m2mCaller("create:organizations"), "POST", "/api/v2/organizations", map[string]any{"name": "quota-org", "token_quota": quota}, e.h.CreateOrganization)
	if rec.Code != 201 {
		t.Fatalf("create org %d", rec.Code)
	}
	orgID := out.(map[string]any)["id"].(string)
	rec, out = e.call(t, e.tn, m2mCaller("update:organizations"), "PATCH", "/api/v2/organizations/"+orgID, map[string]any{"token_quota": nil}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganization(w, r, orgID) })
	if rec.Code != 200 {
		t.Fatal("clear org", rec.Code)
	}
	org, err := e.st.Organizations().Get(t.Context(), e.tn.ID, orgID)
	if err != nil || org.TokenQuota != nil {
		t.Fatal("org quota not cleared")
	}
	rec, out = e.call(t, e.tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", map[string]any{"default_token_quota": map[string]any{"clients": quota}}, e.h.UpdateTenantSettings)
	if rec.Code != 200 {
		t.Fatalf("tenant patch %d", rec.Code)
	}
	tn, err := e.st.Tenants().Get(t.Context(), e.tn.ID)
	if err != nil || tn.DefaultTokenQuota == nil || tn.DefaultTokenQuota.Clients == nil || !tn.DefaultTokenQuota.Clients.Enforce {
		t.Fatal("typed default quota lost")
	}
	rec, out = e.call(t, e.tn, m2mCaller("read:tenant_settings"), "GET", "/api/v2/tenants/settings", nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetTenantSettings(w, r, mgmtapi.GetTenantSettingsParams{})
	})
	if rec.Code != 200 || out.(map[string]any)["default_token_quota"] == nil {
		t.Fatal("public default quota lost")
	}
	for _, body := range []map[string]any{{}, {"client_credentials": map[string]any{}}, {"client_credentials": map[string]any{"per_hour": 0}}, {"client_credentials": map[string]any{"per_hour": 2147483648}}} {
		rec, _ = e.call(t, e.tn, m2mCaller(allClientScopes...), "PATCH", "/api/v2/clients/"+id, map[string]any{"token_quota": body}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) })
		if rec.Code != 400 {
			t.Fatalf("invalid quota accepted %d", rec.Code)
		}
	}
}
func TestQuotaConfigurationCapability(t *testing.T) {
	for _, tc := range []struct {
		name   string
		probe  error
		status int
	}{{"legacy", store.ErrRefreshTokensIIUnavailable, 400}, {"lost", store.ErrRefreshTokensIISupportLost, 500}, {"transport", errors.New("temporary probe failure"), 500}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newClientsEnv(t)
			e.h.Log = slog.New(slog.DiscardHandler)
			e.h.Store = grantCascadeStore{Store: e.st, probe: tc.probe}
			quota := map[string]any{"client_credentials": map[string]any{"per_hour": 1}}
			for _, target := range []string{"client", "organization", "tenant"} {
				var code int
				switch target {
				case "client":
					r, _ := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", map[string]any{"name": "quota", "token_quota": quota}, e.h.CreateClient)
					code = r.Code
				case "organization":
					r, _ := e.call(t, e.tn, m2mCaller("create:organizations"), "POST", "/api/v2/organizations", map[string]any{"name": "quota", "token_quota": quota}, e.h.CreateOrganization)
					code = r.Code
				case "tenant":
					r, _ := e.call(t, e.tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", map[string]any{"default_token_quota": map[string]any{"clients": quota}}, e.h.UpdateTenantSettings)
					code = r.Code
				}
				if code != tc.status {
					t.Fatalf("%s status %d want%d", target, code, tc.status)
				}
			}
		})
	}
}

func TestQuotaPartialUpdates(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Log = slog.New(slog.DiscardHandler)
	q := map[string]any{"client_credentials": map[string]any{"per_hour": 10, "per_day": 50}}
	update := map[string]any{"client_credentials": map[string]any{"enforce": false}}
	rec, out := e.call(t, e.tn, m2mCaller(allClientScopes...), "POST", "/api/v2/clients", map[string]any{"name": "partial-quota", "token_quota": q}, e.h.CreateClient)
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	id := out.(map[string]any)["client_id"].(string)
	rec, _ = e.call(t, e.tn, m2mCaller(allClientScopes...), "PATCH", "/api/v2/clients/"+id, map[string]any{"token_quota": update}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) })
	c, _ := e.st.Clients().Get(t.Context(), e.tn.ID, id)
	if rec.Code != 200 || c.TokenQuota == nil || c.TokenQuota.Enforce || c.TokenQuota.PerHour != 10 || c.TokenQuota.PerDay != 50 {
		t.Fatal("client partial quota lost limits")
	}
	rec, out = e.call(t, e.tn, m2mCaller("create:organizations"), "POST", "/api/v2/organizations", map[string]any{"name": "partial-quota", "token_quota": q}, e.h.CreateOrganization)
	if rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	oid := out.(map[string]any)["id"].(string)
	rec, _ = e.call(t, e.tn, m2mCaller("update:organizations"), "PATCH", "/api/v2/organizations/"+oid, map[string]any{"token_quota": update}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateOrganization(w, r, oid) })
	o, _ := e.st.Organizations().Get(t.Context(), e.tn.ID, oid)
	if rec.Code != 200 || o.TokenQuota == nil || o.TokenQuota.Enforce || o.TokenQuota.PerHour != 10 || o.TokenQuota.PerDay != 50 {
		t.Fatal("org partial quota lost limits")
	}
	defaults := map[string]any{"clients": q, "organizations": q}
	rec, _ = e.call(t, e.tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", map[string]any{"default_token_quota": defaults}, e.h.UpdateTenantSettings)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	rec, _ = e.call(t, e.tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", map[string]any{"default_token_quota": map[string]any{"clients": update}}, e.h.UpdateTenantSettings)
	tn, _ := e.st.Tenants().Get(t.Context(), e.tn.ID)
	if rec.Code != 200 || tn.DefaultTokenQuota.Clients.Enforce || tn.DefaultTokenQuota.Clients.PerHour != 10 || tn.DefaultTokenQuota.Clients.PerDay != 50 || tn.DefaultTokenQuota.Organizations == nil || tn.DefaultTokenQuota.Organizations.PerDay != 50 {
		t.Fatal("tenant partial quota lost limits or subject")
	}
	rec, _ = e.call(t, e.tn, m2mCaller(allClientScopes...), "PATCH", "/api/v2/clients/"+id, map[string]any{"token_quota": map[string]any{"client_credentials": map[string]any{"per_hour": 20}}}, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateClient(w, r, id) })
	c, _ = e.st.Clients().Get(t.Context(), e.tn.ID, id)
	if rec.Code != 200 || c.TokenQuota.PerHour != 20 || c.TokenQuota.PerDay != 50 || c.TokenQuota.Enforce {
		t.Fatal("partial limit update lost other settings")
	}
}

func TestQuotaLegacyMaterializationCapability(t *testing.T) {
	e := newClientsEnv(t)
	e.h.Log = slog.New(slog.DiscardHandler)
	tn, err := e.st.Tenants().Get(t.Context(), e.tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	tn.SettingsExtra = map[string]any{"default_token_quota": map[string]any{"clients": map[string]any{"client_credentials": map[string]any{"per_hour": 1}}}}
	if err := e.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	e.h.Store = grantCascadeStore{Store: e.st, probe: store.ErrRefreshTokensIIUnavailable}
	rec, _ := e.call(t, e.tn, m2mCaller("update:tenant_settings"), "PATCH", "/api/v2/tenants/settings", map[string]any{"friendly_name": "updated"}, e.h.UpdateTenantSettings)
	if rec.Code != 400 {
		t.Fatalf("legacy materialization status %d want400", rec.Code)
	}
}
