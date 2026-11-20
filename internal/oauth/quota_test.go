package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/dpop"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func quotaClient(t *testing.T, f *fixture, q *store.TokenQuota) {
	t.Helper()
	c, err := f.st.Clients().Get(context.Background(), f.tenantID(t, "acme"), "m2m")
	if err != nil {
		t.Fatal(err)
	}
	c.TokenQuota = q
	if err = f.st.Clients().Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}
func quotaDefaults(t *testing.T, f *fixture, q *store.DefaultTokenQuota) {
	t.Helper()
	tn, err := f.st.Tenants().GetByName(context.Background(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	tn.DefaultTokenQuota = q
	if err = f.st.Tenants().Update(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
}
func quotaCall(t *testing.T, f *fixture, extra ...string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	v := cc("m2m", "m2m-secret", "audience", "https://api.acme.test")
	for i := 0; i < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return f.call(t, true, tokenCall{host: "acme.example.test", form: v})
}
func TestQuotaPrecedence(t *testing.T) {
	f := newFixture(t)
	rec, _ := quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "" {
		t.Fatal("unlimited response", rec.Code, rec.Header())
	}
	quotaDefaults(t, f, &store.DefaultTokenQuota{Clients: &store.TokenQuota{Enforce: true, PerHour: 3}})
	rec, _ = quotaCall(t, f)
	if got := rec.Header().Get("Auth0-Client-Quota-Limit"); got != "b=per_hour;q=3;r=2;t=3600" {
		t.Fatalf("default header %q", got)
	}
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 5})
	rec, _ = quotaCall(t, f)
	if got := rec.Header().Get("Auth0-Client-Quota-Limit"); got != "b=per_hour;q=5;r=3;t=3600" {
		t.Fatalf("override header %q", got)
	}
	if rec.Header().Get("Auth0-Organization-Quota-Limit") != "" {
		t.Fatal("organization header without organization")
	}
}
func TestQuotaHeaders(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 10, PerDay: 50})
	rec, _ := quotaCall(t, f)
	if got := rec.Header().Get("Auth0-Client-Quota-Limit"); got != "b=per_hour;q=10;r=9;t=3600,b=per_day;q=50;r=49;t=43200" {
		t.Fatalf("header %q", got)
	}
}
func TestQuotaExceeded(t *testing.T) {
	for _, enforce := range []bool{true, false} {
		t.Run(map[bool]string{true: "enforced", false: "observe"}[enforce], func(t *testing.T) {
			f := newFixture(t)
			quotaClient(t, f, &store.TokenQuota{Enforce: enforce, PerHour: 10})
			capture := &eventRecorder{}
			f.h.Recorder = capture
			for i := 0; i < 10; i++ {
				rec, _ := quotaCall(t, f)
				if rec.Code != 200 {
					t.Fatalf("request %d status %d", i, rec.Code)
				}
			}
			rec, body := quotaCall(t, f)
			if !enforce {
				if rec.Code != 200 {
					t.Fatal(rec.Code)
				}
				return
			}
			if rec.Code != 429 || body["error"] != "too_many_requests" || body["error_description"] != "Client quota exceeded" {
				t.Fatalf("status %d error %v", rec.Code, body["error"])
			}
			if rec.Header().Get("Retry-After") != "3600" || rec.Header().Get("X-RateLimit-Remaining") != "0" || rec.Header().Get("X-RateLimit-Limit") != "10" || rec.Header().Get("X-RateLimit-Reset") != "1791896400" {
				t.Fatal("rate limit headers", rec.Header())
			}
			if capture.events[len(capture.events)-1].Type != "feccft" {
				t.Fatal("missing failure event")
			}
		})
	}
}
func TestQuotaRefusedNoConsume(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 1})
	for _, form := range []url.Values{cc("m2m", "wrong", "audience", "https://api.acme.test"), cc("m2m", "m2m-secret", "audience", "https://api.acme.test", "scope", "unknown")} {
		rec, _ := f.call(t, true, tokenCall{host: "acme.example.test", form: form})
		if rec.Code == 200 {
			t.Fatal("invalid request succeeded")
		}
		if rec.Header().Get("Auth0-Client-Quota-Limit") != "" {
			t.Fatal("refused request leaks quota")
		}
	}
	rec, _ := quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("refused request consumed", rec.Code, rec.Header())
	}
}
func TestQuotaWarnings(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: false, PerHour: 10})
	capture := &eventRecorder{}
	f.h.Recorder = capture
	for i := 0; i < 13; i++ {
		rec, _ := quotaCall(t, f)
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
	}
	var warnings []string
	for _, e := range capture.events {
		if e.Type == "token_quota_consumption_warning" {
			warnings = append(warnings, e.Description)
		}
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings %v", warnings)
	}
	for i, pct := range []string{"60%", "80%", "100%"} {
		if !strings.Contains(warnings[i], pct) {
			t.Fatal("wrong warning", warnings)
		}
	}
}
func TestQuotaWindowRollover(t *testing.T) {
	f := newFixture(t)
	now := fixedNow().Add(59*time.Minute + 59*time.Second)
	f.h.Now = func() time.Time { return now }
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 1, PerDay: 3})
	rec, _ := quotaCall(t, f)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	now = now.Add(time.Second)
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600,b=per_day;q=3;r=1;t=39600" {
		t.Fatal("rollover", rec.Code, rec.Header())
	}
}
func TestQuotaConcurrent(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 10})
	handler := tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthToken))
	codes := make(chan int, 50)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(cc("m2m", "m2m-secret", "audience", "https://api.acme.test").Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	accepted, rejected := 0, 0
	for c := range codes {
		switch c {
		case 200:
			accepted++
		case 429:
			rejected++
		default:
			t.Fatalf("unexpected status %d", c)
		}
	}
	if accepted != 10 || rejected != 40 {
		t.Fatalf("accepted %d rejected %d", accepted, rejected)
	}
}

func quotaOrganization(t *testing.T, f *fixture, q *store.TokenQuota) string {
	t.Helper()
	tid := f.tenantID(t, "acme")
	org := &store.Organization{TenantID: tid, ID: "org_0000000000000001", Name: "quota-org", TokenQuota: q}
	if err := f.st.Organizations().Create(t.Context(), org, nil); err != nil {
		t.Fatal(err)
	}
	g, err := f.st.ClientGrants().Find(t.Context(), tid, "m2m", acmeAPI, store.SubjectTypeClient)
	if err != nil {
		t.Fatal(err)
	}
	g.OrganizationUsage = store.OrgUsageAllow
	g.AllowAnyOrganization = true
	if err = f.st.ClientGrants().Update(t.Context(), g); err != nil {
		t.Fatal(err)
	}
	return org.ID
}
func TestQuotaOrganization(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 5})
	quotaDefaults(t, f, &store.DefaultTokenQuota{Organizations: &store.TokenQuota{Enforce: true, PerHour: 4}})
	id := quotaOrganization(t, f, &store.TokenQuota{Enforce: true, PerHour: 1})
	rec, _ := quotaCall(t, f, "organization", id)
	if rec.Code != 200 || rec.Header().Get("Auth0-Organization-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("override", rec.Code, rec.Header())
	}
	rec, body := quotaCall(t, f, "organization", id)
	if rec.Code != 429 || body["error_description"] != "Organization quota exceeded" || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=5;r=4;t=3600" {
		t.Fatal("organization refusal consumed client", rec.Code, rec.Header())
	}
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=5;r=3;t=3600" || rec.Header().Get("Auth0-Organization-Quota-Limit") != "" {
		t.Fatal("plain exchange", rec.Code, rec.Header())
	}
}

type quotaFailureStore struct {
	store.Store
	failure error
}

func (s quotaFailureStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(quotaFailureStore{Store: tx, failure: s.failure}) })
}
func (s quotaFailureStore) TokenQuotas() store.TokenQuotas {
	return quotaFailureRepo{TokenQuotas: s.Store.TokenQuotas(), failure: s.failure}
}

type quotaFailureRepo struct {
	store.TokenQuotas
	failure error
}

func (r quotaFailureRepo) Consume(ctx context.Context, tid string, subjects []store.QuotaSubject, now time.Time) ([]store.QuotaState, error) {
	if _, err := r.TokenQuotas.Consume(ctx, tid, subjects, now); err != nil {
		return nil, err
	}
	return nil, r.failure
}
func TestQuotaStoreRollback(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 1})
	base := f.st
	f.h.Store = quotaFailureStore{Store: base, failure: errors.New("temporary counter failure")}
	capture := &eventRecorder{}
	f.h.Recorder = capture
	rec, _ := quotaCall(t, f)
	if rec.Code != 500 || rec.Header().Get("Auth0-Client-Quota-Limit") != "" {
		t.Fatal("store failure", rec.Code, rec.Header())
	}
	for _, e := range capture.events {
		if e.Type == "token_quota_consumption_warning" {
			t.Fatal("rollback logged warning")
		}
	}
	f.h.Store = base
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("rollback consumed", rec.Code, rec.Header())
	}
}
func TestQuotaSigningFailureNoConsume(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 1})
	f.setAPISigning(t, "HS256", "")
	rec, _ := quotaCall(t, f)
	if rec.Code != 500 {
		t.Fatal("expected signer error", rec.Code)
	}
	f.setAPISigning(t, "RS256", "")
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("sign failure counted", rec.Code, rec.Header())
	}
}
func TestQuotaLegacyDefault(t *testing.T) {
	f := newFixture(t)
	tn, err := f.st.Tenants().GetByName(t.Context(), "acme")
	if err != nil {
		t.Fatal(err)
	}
	tn.SettingsExtra["default_token_quota"] = map[string]any{"clients": map[string]any{"client_credentials": map[string]any{"per_hour": 1}}}
	if err = f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	rec, _ := quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") == "" {
		t.Fatal("legacy quota ignored", rec.Code)
	}
	rec, _ = quotaCall(t, f)
	if rec.Code != 429 {
		t.Fatal("legacy quota not enforced", rec.Code)
	}
}

type quotaFinalHookStore struct {
	store.Store
	calls int
	hook  func()
}

func (s *quotaFinalHookStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	s.calls++
	if s.calls == 2 {
		s.hook()
	}
	return s.Store.WithTx(ctx, fn)
}
func TestQuotaAuthorizationAtMint(t *testing.T) {
	for _, change := range []string{"scopes", "api lifetime", "proof", "grant type", "grant deleted", "organization"} {
		t.Run(change, func(t *testing.T) {
			f := newFixture(t)
			quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 10})
			orgID := ""
			if change == "organization" {
				orgID = quotaOrganization(t, f, nil)
			}
			f.h.Store = &quotaFinalHookStore{Store: f.st, hook: func() {
				tid := f.tenantID(t, "acme")
				switch change {
				case "scopes":
					g, _ := f.st.ClientGrants().Find(t.Context(), tid, "m2m", acmeAPI, store.SubjectTypeClient)
					g.Scopes = nil
					if err := f.st.ClientGrants().Update(t.Context(), g); err != nil {
						t.Fatal(err)
					}
				case "api lifetime":
					rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), tid, acmeAPI)
					rs.TokenLifetime = 2
					if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
						t.Fatal(err)
					}
				case "proof", "grant type":
					c, _ := f.st.Clients().Get(t.Context(), tid, "m2m")
					if change == "proof" {
						c.RequireProofOfPossession = true
					} else {
						c.GrantTypes = nil
					}
					if err := f.st.Clients().Update(t.Context(), c); err != nil {
						t.Fatal(err)
					}
				case "grant deleted":
					g, _ := f.st.ClientGrants().Find(t.Context(), tid, "m2m", acmeAPI, store.SubjectTypeClient)
					if err := f.st.ClientGrants().Delete(t.Context(), tid, g.ID); err != nil {
						t.Fatal(err)
					}
				case "organization":
					if err := f.st.Organizations().Delete(t.Context(), tid, orgID); err != nil {
						t.Fatal(err)
					}
				}
			}}
			extras := []string{}
			if orgID != "" {
				extras = []string{"organization", orgID}
			}
			rec, _ := quotaCall(t, f, extras...)
			if rec.Code == 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "" {
				t.Fatal("changed authorization minted or exposed quota", rec.Code, rec.Header())
			}
			states, err := f.st.TokenQuotas().Peek(t.Context(), f.tenantID(t, "acme"), []store.QuotaSubject{{Kind: "client", ID: "m2m", Quota: store.TokenQuota{Enforce: true, PerHour: 10}}}, fixedNow())
			if err != nil || states[0].Buckets[0].Remaining != 10 {
				t.Fatal("refused mint consumed quota", err)
			}
		})
	}
}
func TestQuotaActionRefusalNoConsume(t *testing.T) {
	f := newActionsFixture(t)
	quotaClient(t, f.fixture, &store.TokenQuota{Enforce: true, PerHour: 1})
	f.actions.CredentialsExchange(t, f.tid, "quota-deny", `exports.onExecuteCredentialsExchange=async(event,api)=>{api.access.deny('invalid_scope','not allowed');};`)
	rec, _ := quotaCall(t, f.fixture)
	if rec.Code == 200 {
		t.Fatal("denied Action minted")
	}
	states, err := f.st.TokenQuotas().Peek(t.Context(), f.tid, []store.QuotaSubject{{Kind: "client", ID: "m2m", Quota: store.TokenQuota{Enforce: true, PerHour: 1}}}, fixedNow())
	if err != nil || states[0].Buckets[0].Remaining != 1 {
		t.Fatal("Action refusal counted", err)
	}
}
func TestQuotaLegacyInvalidAndTypedPrecedence(t *testing.T) {
	f := newFixture(t)
	tn, _ := f.st.Tenants().GetByName(t.Context(), "acme")
	tn.SettingsExtra["default_token_quota"] = map[string]any{"clients": map[string]any{"client_credentials": map[string]any{"per_hour": 0}}}
	if err := f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	rec, _ := quotaCall(t, f)
	if rec.Code != 500 {
		t.Fatal("invalid legacy quota became unlimited", rec.Code)
	}
	tn.DefaultTokenQuota = &store.DefaultTokenQuota{Clients: &store.TokenQuota{Enforce: true, PerHour: 1}}
	if err := f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("typed quota not authoritative", rec.Code)
	}
}

func TestQuotaDPoPReplayNoConsume(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 2})
	f.h.DPoP = &dpop.Service{Store: f.st, Wrapper: f.wrapper, Now: fixedNow}
	rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), f.tenantID(t, "acme"), acmeAPI)
	rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop", Required: true, RequiredFor: "all_clients"}
	if err := f.st.ResourceServers().Update(t.Context(), rs); err != nil {
		t.Fatal(err)
	}
	key := dpopKey(t)
	proof := dpopJWT(t, key, "/oauth/token", "")
	form := cc("m2m", "m2m-secret", "audience", acmeAPI)
	for i := 0; i < 2; i++ {
		rec, body := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": proof}})
		if i == 0 && rec.Code != 200 {
			t.Fatal("proof failed", rec.Code, body["error"])
		}
		if i == 1 && (rec.Code != 400 || body["error"] != "invalid_dpop_proof" || rec.Header().Get("Auth0-Client-Quota-Limit") != "") {
			t.Fatal("replay not refused", rec.Code)
		}
	}
	rec, _ := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=2;r=0;t=3600" {
		t.Fatal("replay consumed quota", rec.Code, rec.Header())
	}
}

type quotaBrokenSigner struct{ store.SigningKeys }

func (s quotaBrokenSigner) List(context.Context, string) ([]*store.SigningKey, error) {
	return nil, errors.New("temporary signing key failure")
}
func TestQuotaSignerFailureNoConsume(t *testing.T) {
	f := newFixture(t)
	quotaClient(t, f, &store.TokenQuota{Enforce: true, PerHour: 1})
	f.h.Minter.Keys = keys.NewManager(quotaBrokenSigner{f.st.SigningKeys()}, f.wrapper)
	rec, _ := quotaCall(t, f)
	if rec.Code != 500 || rec.Header().Get("Auth0-Client-Quota-Limit") != "" {
		t.Fatal("failed signer quota", rec.Code)
	}
	f.h.Minter.Keys = f.keys
	rec, _ = quotaCall(t, f)
	if rec.Code != 200 || rec.Header().Get("Auth0-Client-Quota-Limit") != "b=per_hour;q=1;r=0;t=3600" {
		t.Fatal("signing failure counted", rec.Code)
	}
}
