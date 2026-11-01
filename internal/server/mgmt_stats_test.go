package server

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
)

func TestStatsScopeThroughServer(t *testing.T) {
	seed := strings.Replace(mgmtSeed, `"read:connections", "create:connections"`, `"read:stats", "read:connections", "create:connections"`, 1)
	h, st := newMgmtEnvSeed(t, seed, nil)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	reader := m2mToken(t, h, "acme.example.test", acmeMgmtAPI)
	op, _ := operatorToken(t, st, "stats-admin@example.test")
	scoped, scopedID := operatorToken(t, st, "stats-scoped@example.test")
	tn, err := st.Tenants().GetByName(t.Context(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	other, err := tenantsetup.UpsertTenant(t.Context(), st, "other", time.Now(), func(tn *store.Tenant) error {
		tn.Domains = []string{"other.example.test"}
		tn.CanonicalHost = "other.example.test"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if err := st.Logs().AppendLogs(t.Context(), nil, []store.DailyStatDelta{{TenantID: tn.ID, Day: day, Logins: 4}, {TenantID: other.ID, Day: day, Logins: 999}}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(t.Context(), &store.User{TenantID: tn.ID, UserID: "auth0|stats", LastLogin: timePtr(time.Now())}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().Create(t.Context(), &store.User{TenantID: other.ID, UserID: "auth0|stats", LastLogin: timePtr(time.Now())}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"daily?from=20261030&to=20261030", "active-users"} {
		endpoint := "https://acme.example.test/api/v2/stats/" + path
		for _, tc := range []struct {
			token string
			want  int
		}{{"", 401}, {reader, 403}, {admin, 200}, {op, 200}, {scoped, 200}} {
			w, out := sendRaw(h, "GET", endpoint, tc.token, nil)
			if w.Code != tc.want {
				t.Fatal(path, w.Code, w.Body)
			}
			if tc.want == 200 {
				if strings.HasPrefix(path, "daily") {
					rows, ok := out.([]any)
					if !ok || len(rows) != 1 || rows[0].(map[string]any)["logins"] != float64(4) || rows[0].(map[string]any)["date"] != "2026-10-30T00:00:00Z" {
						t.Fatal(out)
					}
				} else if out != float64(1) {
					t.Fatal(out)
				}
			}
		}
	}
	// Live operator grants override the token's original wildcard immediately.
	w, _ := sendRaw(h, "PATCH", "https://"+mgmtSystemHost+"/api/system/operators/"+url.PathEscape(scopedID), op, map[string]any{"tenants": []string{"other"}})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	for _, path := range []string{"daily", "active-users"} {
		w, _ := sendRaw(h, "GET", "https://acme.example.test/api/v2/stats/"+path, scoped, nil)
		if w.Code != 403 {
			t.Fatal(path, w.Code, w.Body)
		}
		w, _ = sendRaw(h, "GET", "https://other.example.test/api/v2/stats/"+path, admin, nil)
		if w.Code != 401 {
			t.Fatal("cross-tenant M2M", path, w.Code, w.Body)
		}
	}
	for _, q := range []string{"from=20260229", "from=20261030&from=20261030", "unknown=x", "from=00000101&to=99991231"} {
		w, out := sendRaw(h, "GET", "https://acme.example.test/api/v2/stats/daily?"+q, admin, nil)
		if w.Code != 400 || errCode(out) != "invalid_query_string" {
			t.Fatal(q, w.Code, w.Body)
		}
	}
	rs, err := st.ResourceServers().GetByIdentifier(t.Context(), tn.ID, acmeMgmtAPI)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range rs.Scopes {
		found = found || s.Value == "read:stats"
	}
	if !found {
		t.Fatal("read:stats missing from provisioned management scope catalog")
	}
}

func TestDailyStatsAndActiveUsersThroughServerUnavailable(t *testing.T) {
	h, st := newMgmtEnvSeed(t, mgmtSeed, func(d *Deps) { d.Store = serverStreamsUnavailable{d.Store} })
	op, _ := operatorToken(t, st, "stats-capability@example.test")
	for _, path := range []string{"daily", "active-users"} {
		w, out := sendRaw(h, http.MethodGet, "https://acme.example.test/api/v2/stats/"+path, op, nil)
		if w.Code != 501 || errCode(out) != "logs_unavailable" {
			t.Fatal(path, w.Code, w.Body)
		}
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestDailyStatsAndActiveUsersMalformedQueryThroughServer(t *testing.T) {
	seed := strings.Replace(mgmtSeed, `"read:connections", "create:connections"`, `"read:stats", "read:connections", "create:connections"`, 1)
	h, _ := newMgmtEnvSeed(t, seed, nil)
	admin := clientToken(t, h, "acme.example.test", acmeMgmtAPI, "admin", "admin-s3cret")
	for _, path := range []string{"daily", "active-users"} {
		for _, query := range []string{"from=20261030;to=20261031", "unknown=%zz", "from=%", "unknown;"} {
			t.Run(path+"/"+query, func(t *testing.T) {
				w, out := sendRaw(h, "GET", "https://acme.example.test/api/v2/stats/"+path+"?"+query, admin, nil)
				if w.Code != 400 || errCode(out) != "invalid_query_string" {
					t.Fatal(w.Code, w.Body)
				}
			})
		}
	}
}
