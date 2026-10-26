package mgmt_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// readyDomain stores an API custom domain in the given readiness.
func (e *usersEnv) customDomain(t *testing.T, tenantID, id, host string, ready bool) *store.CustomDomain {
	t.Helper()
	ctx := context.Background()
	d := &store.CustomDomain{TenantID: tenantID, ID: id, Domain: host, Type: customdomain.TypeManaged, Generation: 1,
		Status: customdomain.StatusPending, Lifecycle: customdomain.LifecycleIssuing, DomainMetadata: map[string]string{"brand": "acme"}}
	if ready {
		d.Status, d.Lifecycle = customdomain.StatusReady, customdomain.LifecycleActive
		d.ActiveCertificateKey = "cert/" + tenantID + "/" + id
		if err := e.st.TLSAssets().Put(ctx, &store.TLSAsset{Key: d.ActiveCertificateKey, Kind: store.TLSAssetCertificate, TenantID: tenantID, DomainID: id, Generation: d.Generation, PublicData: store.TLSPublicData{Version: 1, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.st.CustomDomains().Create(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := e.st.CustomDomains().PutHost(ctx, &store.HostBinding{Host: host, TenantID: tenantID, DomainID: id, Generation: 1, Kind: store.HostPublic, Active: ready}); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestDomainNotificationOrigins(t *testing.T) {
	ctx := context.Background()
	e := newUsersEnv(t)
	u := e.mustCreate(t, map[string]any{"email": "kim@acme.test"})
	userID := u["user_id"].(string)
	ready := e.customDomain(t, e.tn.ID, "cd_ready", "id.acme.test", true)
	e.customDomain(t, e.tn.ID, "cd_pending", "pending.acme.test", false)
	e.customDomain(t, e.sys.ID, "cd_foreign", "foreign.example.test", true)

	ticket := func(header string) (int, string) {
		t.Helper()
		caller := m2mCaller("create:user_tickets")
		rec, out := e.callWith(t, e.tn, caller, "POST", "/api/v2/tickets/password-change", map[string]any{"user_id": userID},
			http.Header{"Auth0-Custom-Domain": {header}}, e.h.CreatePasswordChangeTicket)
		m, _ := out.(map[string]any)
		link, _ := m["ticket"].(string)
		return rec.Code, link
	}
	countTickets := func() int {
		n, _ := e.st.PasswordResetTickets().DeleteByUser(ctx, e.tn.ID, userID)
		return n
	}

	// Explicit selection, then canonical; request Host never decides.
	if code, link := ticket("ID.acme.test"); code != 201 || !strings.HasPrefix(link, "https://id.acme.test/u/reset-verify?ticket=") {
		t.Fatalf("explicit = %d %q", code, link)
	}
	if code, link := ticket(""); code != 201 || !strings.HasPrefix(link, "https://login.acme.test/") {
		t.Fatalf("canonical = %d %q", code, link)
	}
	countTickets()
	// Invalid, pending and foreign selections fail before any ticket exists.
	for _, h := range []string{"pending.acme.test", "foreign.example.test", "nobody.test", "https://id.acme.test"} {
		if code, _ := ticket(h); code != http.StatusServiceUnavailable {
			t.Errorf("header %q = %d", h, code)
		}
	}
	if n := countTickets(); n != 0 {
		t.Fatalf("refused selections created %d tickets", n)
	}
	// A usable default is used implicitly; an unusable one falls back to
	// canonical while the pointer remains.
	if err := e.st.CustomDomains().SetDefault(ctx, e.tn.ID, ready.ID); err != nil {
		t.Fatal(err)
	}
	if _, link := ticket(""); !strings.HasPrefix(link, "https://id.acme.test/") {
		t.Fatalf("default = %q", link)
	}
	cur, _ := e.st.CustomDomains().Get(ctx, e.tn.ID, ready.ID)
	cur.Status, cur.Lifecycle = customdomain.StatusPending, customdomain.LifecycleSuspended
	if err := e.st.CustomDomains().Update(ctx, cur, cur.Revision); err != nil {
		t.Fatal(err)
	}
	if _, link := ticket(""); !strings.HasPrefix(link, "https://login.acme.test/") {
		t.Fatalf("unusable default = %q", link)
	}
	if id, _ := e.st.CustomDomains().GetDefault(ctx, e.tn.ID); id != ready.ID {
		t.Fatal("fallback cleared the default pointer")
	}
	cur.Status, cur.Lifecycle = customdomain.StatusReady, customdomain.LifecycleActive
	if err := e.st.CustomDomains().Update(ctx, cur, cur.Revision); err != nil {
		t.Fatal(err)
	}

	// Verification email jobs persist the selection at creation.
	job := func(header string) (int, map[string]any) {
		rec, out := e.callWith(t, e.tn, m2mCaller("update:users"), "POST", "/api/v2/jobs/verification-email", map[string]any{"user_id": userID},
			http.Header{"Auth0-Custom-Domain": {header}}, e.h.CreateVerificationEmailJob)
		m, _ := out.(map[string]any)
		return rec.Code, m
	}
	code, out := job("id.acme.test")
	if code != 201 {
		t.Fatalf("job = %d %v", code, out)
	}
	j, _ := e.st.Jobs().Get(ctx, e.tn.ID, out["id"].(string))
	if j.Params["selected_origin"] != "id.acme.test" {
		t.Fatalf("job params = %v", j.Params)
	}
	if err := e.st.CustomDomains().SetDefault(ctx, e.tn.ID, ""); err != nil {
		t.Fatal(err)
	}
	if code, out := job(""); code != 201 {
		t.Fatalf("implicit job = %d", code)
	} else if j, _ := e.st.Jobs().Get(ctx, e.tn.ID, out["id"].(string)); j.Params["selected_origin"] != "login.acme.test" {
		t.Fatalf("implicit job params = %v", j.Params)
	}
	if code, _ := job("pending.acme.test"); code != http.StatusServiceUnavailable {
		t.Fatalf("pending job = %d", code)
	}
}
