package oauth

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"
)

func onlineFixture(t *testing.T, enabled bool, mode string, ephemeral bool) (*fixture, *store.LoginSession) {
	t.Helper()
	f := newFixture(t)
	ctx := t.Context()
	tid := f.tenantID(t, "acme")
	rs, e := f.st.ResourceServers().GetByIdentifier(ctx, tid, acmeAPI)
	if e != nil {
		t.Fatal(e)
	}
	rs.AllowOnlineAccess = enabled
	rs.AllowOnlineAccessWithEphemeralSessions = ephemeral
	if e = f.st.ResourceServers().Update(ctx, rs); e != nil {
		t.Fatal(e)
	}
	u, e := f.st.Users().FindByLogin(ctx, tid, "Username-Password-Authentication", "alice@acme.test")
	if e != nil {
		t.Fatal(e)
	}
	s := &store.LoginSession{TenantID: tid, ID: "sid-1", Origin: "https://acme.example.test", TokenHash: secrets.HashToken(secrets.RandomString(43)), UserID: u.UserID, CookieMode: mode, AuthenticatedAt: fixedNow(), CreatedAt: fixedNow(), UpdatedAt: fixedNow(), LastInteractedAt: fixedNow(), ExpiresAt: fixedNow().Add(24 * time.Hour), IdleExpiresAt: fixedNow().Add(time.Hour)}
	if e = f.st.Sessions().Create(ctx, s); e != nil {
		t.Fatal(e)
	}
	return f, s
}
func issueOnline(t *testing.T, f *fixture) (int, map[string]any) {
	t.Helper()
	code := f.issueCode(t, "rt-web", "https://rtweb.acme.test/cb", acmeAPI, []string{"openid", "online_access", "read:things"}, "")
	form := codeForm(code, "rt-web", "https://rtweb.acme.test/cb", "")
	form.Set("client_secret", "rt-web-secret")
	r, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	return r.Code, b
}
func refreshOnline(t *testing.T, f *fixture, raw string) (int, map[string]any) {
	t.Helper()
	form := refreshForm("rt-web", raw)
	form.Set("client_secret", "rt-web-secret")
	return f.refresh(t, form)
}
func TestORTIssue(t *testing.T) {
	for _, tc := range []struct {
		name, mode               string
		enabled, ephemeral, want bool
	}{{"persistent", "persistent", true, false, true}, {"disabled", "persistent", false, false, false}, {"ephemeral disabled", "non-persistent", true, false, false}, {"ephemeral enabled", "non-persistent", true, true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			f, s := onlineFixture(t, tc.enabled, tc.mode, tc.ephemeral)
			status, b := issueOnline(t, f)
			if status != 200 {
				t.Fatalf("status %d error %v", status, b["error"])
			}
			raw, _ := b["refresh_token"].(string)
			if (raw != "") != tc.want {
				t.Fatalf("ORT present %v want %v", raw != "", tc.want)
			}
			if tc.want {
				rt := f.storedRT(t, raw)
				if rt.Access != "online" || rt.SessionID != s.ID || rt.Rotating || !rt.ExpiresAt.Equal(s.ExpiresAt) || !rt.IdleExpiresAt.IsZero() || !slices.Contains(rt.Scopes, "online_access") {
					t.Fatal("incorrect online grant")
				}
			} else if sc, _ := b["scope"].(string); slices.Contains(splitScopes(sc), "online_access") {
				t.Fatal("unsupported online scope returned")
			}
		})
	}
}
func splitScopes(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}
func TestORTReuse(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	status, b := issueOnline(t, f)
	raw, _ := b["refresh_token"].(string)
	if status != 200 || raw == "" {
		t.Fatal("missing online token")
	}
	now := fixedNow().Add(30 * time.Minute)
	f.h.Now = func() time.Time { return now }
	for i := 0; i < 2; i++ {
		status, b = refreshOnline(t, f, raw)
		if status != 200 || b["refresh_token"] != nil {
			t.Fatalf("reuse status %d error %v successor %v", status, b["error"], b["refresh_token"] != nil)
		}
	}
	got, e := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID)
	if e != nil || !got.LastInteractedAt.Equal(now) || !got.ExpiresAt.Equal(s.ExpiresAt) || !got.IdleExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("session not extended within absolute lifetime")
	}
}
func TestORTSessionLifecycle(t *testing.T) {
	for _, mode := range []string{"delete", "expired", "logout"} {
		t.Run(mode, func(t *testing.T) {
			f, s := onlineFixture(t, true, "persistent", false)
			_, b := issueOnline(t, f)
			raw, _ := b["refresh_token"].(string)
			if raw == "" {
				t.Fatal("missing online token")
			}
			if mode == "logout" {
				rawCookie := secrets.RandomString(43)
				if e := f.st.Sessions().Delete(t.Context(), s.TenantID, s.ID); e != nil {
					t.Fatal(e)
				}
				s.TokenHash = secrets.HashToken(rawCookie)
				if e := f.st.Sessions().Create(t.Context(), s); e != nil {
					t.Fatal(e)
				}
				req := httptest.NewRequest("GET", "https://acme.example.test/logout", nil)
				req.AddCookie(&http.Cookie{Name: session.CookieName, Value: rawCookie})
				rec := httptest.NewRecorder()
				tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					res, _ := tenant.FromContext(r.Context())
					_, e := (&session.Manager{Store: f.st, Now: f.h.Now}).End(r.Context(), w, r, res.Tenant)
					if e != nil {
						t.Fatal(e)
					}
				})).ServeHTTP(rec, req)
			} else if mode == "delete" {
				if e := f.st.Sessions().Delete(t.Context(), s.TenantID, s.ID); e != nil {
					t.Fatal(e)
				}
			} else {
				f.h.Now = func() time.Time { return s.IdleExpiresAt }
			}
			status, b := refreshOnline(t, f, raw)
			if status != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("status %d error %v", status, b["error"])
			}
		})
	}
}

func TestORTRevokeEndsSession(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	_, b := issueOnline(t, f)
	raw, _ := b["refresh_token"].(string)
	if raw == "" {
		t.Fatal("missing online token")
	}
	_, second := issueOnline(t, f)
	other, _ := second["refresh_token"].(string)
	offline, _ := f.issueRefresh(t, "rt-web", []string{"openid", "offline_access"}, acmeAPI)
	status, b := f.revoke(t, url.Values{"client_id": {"rt-web"}, "client_secret": {"rt-web-secret"}, "token": {raw}})
	if status != 200 {
		t.Fatalf("revoke %d error %v", status, b["error"])
	}
	if _, e := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID); e == nil {
		t.Fatal("ORT revoke kept session")
	}
	status, b = refreshOnline(t, f, other)
	if status != 400 || b["error"] != "invalid_grant" {
		t.Fatal("session sibling ORT survived revoke")
	}
	status, b = refreshOnline(t, f, offline)
	if status != 200 {
		t.Fatal("ORT session revoke killed offline token")
	}
}

func TestORTActionRevoke(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	env := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = env.Engine
	env.PostLogin(t, s.TenantID, "online-revoke", `exports.onExecutePostLogin=async(event,api)=>{if(event.refresh_token?.access!=='online'||!event.session?.id)throw new Error('missing online event');api.refreshToken.revoke('session ended');};`)
	_, b := issueOnline(t, f)
	raw, _ := b["refresh_token"].(string)
	if raw == "" {
		t.Fatal("missing token")
	}
	status, b := refreshOnline(t, f, raw)
	if status != 400 || b["error"] != "invalid_grant" {
		t.Fatalf("action revoke status %d error %v", status, b["error"])
	}
	if _, e := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID); e == nil {
		t.Fatal("Action kept session")
	}
}

func TestORTRequiresDPoP(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	key := dpopKey(t)
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", acmeAPI, []string{"openid", "online_access", "read:things"}, pkceChallenge)
	form := codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)
	r, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
	if r.Code != 400 || b["error"] != "invalid_dpop_proof" {
		t.Fatal("public ORT accepted without proof")
	}
	ac, e := f.st.AuthCodes().Get(t.Context(), s.TenantID, secrets.HashToken(code))
	if e != nil || ac.UsedAt != nil {
		t.Fatal("missing proof consumed code")
	}
	r, b = f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
	if r.Code != 400 || b["error"] != "use_dpop_nonce" {
		t.Fatal("missing nonce accepted")
	}
	nonce := r.Header().Get("DPoP-Nonce")
	r, b = f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", nonce)}})
	raw, _ := b["refresh_token"].(string)
	if r.Code != 200 || raw == "" {
		t.Fatalf("ORT issue status %d error %v", r.Code, b["error"])
	}
	rt := f.storedRT(t, raw)
	if rt.DPoPJKT == "" {
		t.Fatal("public ORT unbound")
	}
	for _, proof := range []string{"", dpopJWT(t, dpopKey(t), "/oauth/token", nonce)} {
		headers := map[string]string{}
		if proof != "" {
			headers["DPoP"] = proof
		}
		r, b = f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: headers})
		if r.Code != 400 {
			t.Fatalf("missing/wrong key status %d", r.Code)
		}
		current, _ := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID)
		if !current.LastInteractedAt.Equal(s.LastInteractedAt) {
			t.Fatal("invalid proof extended session")
		}
	}
	r, b = f.call(t, false, tokenCall{host: "acme.example.test", form: refreshForm("rt-spa", raw), header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", nonce)}})
	if r.Code != 200 || b["refresh_token"] != nil {
		t.Fatalf("ORT reuse %d error %v", r.Code, b["error"])
	}
}
func TestORTOtherGrants(t *testing.T) {
	for _, grant := range []string{"device", "password"} {
		t.Run(grant, func(t *testing.T) {
			f, _ := onlineFixture(t, true, "persistent", false)
			var form url.Values
			if grant == "device" {
				code, _ := f.newDeviceCode(t, "dev", store.DeviceCodeApproved, f.aliceID(t), []string{"openid", "online_access", "read:things"})
				form = deviceForm("dev", code)
			} else {
				form = url.Values{"grant_type": {"password"}, "client_id": {"ropg"}, "client_secret": {"ropg-secret"}, "username": {"alice@acme.test"}, "password": {"alice password 1"}, "scope": {"openid online_access read:things"}, "audience": {acmeAPI}}
			}
			r, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form})
			if r.Code != 200 || b["refresh_token"] != nil || slices.Contains(splitScopes(b["scope"].(string)), "online_access") {
				t.Fatalf("other grant status %d online token %v", r.Code, b["refresh_token"] != nil)
			}
		})
	}
}
func TestOfflineTokensSurviveSessionDelete(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	raw, _ := f.issueRefresh(t, "rt-web", []string{"openid", "offline_access"}, acmeAPI)
	if e := f.st.Sessions().Delete(t.Context(), s.TenantID, s.ID); e != nil {
		t.Fatal(e)
	}
	status, b := refreshOnline(t, f, raw)
	if status != 200 {
		t.Fatalf("offline refresh %d error %v", status, b["error"])
	}
}
func TestORTAtMint(t *testing.T) {
	for _, mode := range []string{"delete", "expiry", "API disabled", "grant removed"} {
		t.Run(mode, func(t *testing.T) {
			f, s := onlineFixture(t, true, "persistent", false)
			_, b := issueOnline(t, f)
			raw, _ := b["refresh_token"].(string)
			if raw == "" {
				t.Fatal("missing token")
			}
			f.h.Store = nativeBeforeTxStore{f.st, func() {
				switch mode {
				case "delete":
					if e := f.st.Sessions().Delete(t.Context(), s.TenantID, s.ID); e != nil {
						t.Fatal(e)
					}
				case "expiry":
					f.h.Now = func() time.Time { return s.IdleExpiresAt }
				case "API disabled":
					rs, _ := f.st.ResourceServers().GetByIdentifier(t.Context(), s.TenantID, acmeAPI)
					rs.AllowOnlineAccess = false
					if e := f.st.ResourceServers().Update(t.Context(), rs); e != nil {
						t.Fatal(e)
					}
				case "grant removed":
					c, _ := f.st.Clients().Get(t.Context(), s.TenantID, "rt-web")
					c.GrantTypes = []string{"authorization_code"}
					if e := f.st.Clients().Update(t.Context(), c); e != nil {
						t.Fatal(e)
					}
				}
			}}
			status, b := refreshOnline(t, f, raw)
			if status != 400 || b["error"] != "invalid_grant" {
				t.Fatalf("changed online source accepted %d error %v", status, b["error"])
			}
			if mode != "delete" {
				got, _ := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID)
				if !got.LastInteractedAt.Equal(s.LastInteractedAt) {
					t.Fatal("refused exchange extended session")
				}
			}
		})
	}
}

func TestORTDisabledPublicScope(t *testing.T) {
	f, _ := onlineFixture(t, false, "persistent", false)
	code := f.issueCode(t, "rt-spa", "https://rt.acme.test/cb", acmeAPI, []string{"openid", "online_access"}, pkceChallenge)
	r, b := f.call(t, false, tokenCall{host: "acme.example.test", form: codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier)})
	if r.Code != 200 || b["refresh_token"] != nil {
		t.Fatalf("disabled online scope status %d error %v", r.Code, b["error"])
	}
}

func TestORTConfidentialProof(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	key := dpopKey(t)
	code := f.issueCode(t, "rt-web", "https://rtweb.acme.test/cb", acmeAPI, []string{"openid", "online_access"}, "")
	form := codeForm(code, "rt-web", "https://rtweb.acme.test/cb", "")
	form.Set("client_secret", "rt-web-secret")
	r, b := f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
	raw, _ := b["refresh_token"].(string)
	if r.Code != 200 || raw == "" {
		t.Fatalf("issue %d error %v", r.Code, b["error"])
	}
	if rt := f.storedRT(t, raw); rt.DPoPJKT == "" {
		t.Fatal("confidential proof was not retained")
	}
	status, _ := refreshOnline(t, f, raw)
	if status != 400 {
		t.Fatal("bound confidential token accepted without proof")
	}
	form = refreshForm("rt-web", raw)
	form.Set("client_secret", "rt-web-secret")
	r, b = f.call(t, false, tokenCall{host: "acme.example.test", form: form, header: map[string]string{"DPoP": dpopJWT(t, key, "/oauth/token", "")}})
	if r.Code != 200 || b["refresh_token"] != nil {
		t.Fatalf("refresh %d error %v", r.Code, b["error"])
	}
	if current, _ := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID); !current.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("absolute session deadline changed")
	}
}
func TestORTIdlePolicy(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	_, b := issueOnline(t, f)
	raw, _ := b["refresh_token"].(string)
	if raw == "" {
		t.Fatal("missing token")
	}
	tn, err := f.st.Tenants().Get(t.Context(), s.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	tn.IdleSessionLifetime = 7200
	if err = f.st.Tenants().Update(t.Context(), tn); err != nil {
		t.Fatal(err)
	}
	now := fixedNow().Add(30 * time.Minute)
	f.h.Now = func() time.Time { return now }
	status, b := refreshOnline(t, f, raw)
	if status != 200 {
		t.Fatalf("refresh %d error %v", status, b["error"])
	}
	current, err := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID)
	if err != nil || !current.IdleExpiresAt.Equal(now.Add(2*time.Hour)) || !current.ExpiresAt.Equal(s.ExpiresAt) {
		t.Fatal("current session idle policy not respected")
	}
}

type ortUnavailableSessionStore struct{ store.Store }

func (s ortUnavailableSessionStore) Sessions() store.Sessions {
	return ortUnavailableSessions{s.Store.Sessions()}
}

type ortUnavailableSessions struct{ store.Sessions }

func (s ortUnavailableSessions) Get(context.Context, string, string) (*store.LoginSession, error) {
	return nil, errors.New("temporary session read failure")
}
func TestORTSessionReadFailure(t *testing.T) {
	f, _ := onlineFixture(t, true, "persistent", false)
	_, b := issueOnline(t, f)
	raw, _ := b["refresh_token"].(string)
	if raw == "" {
		t.Fatal("missing token")
	}
	f.h.Store = ortUnavailableSessionStore{f.st}
	status, b := refreshOnline(t, f, raw)
	if status != 500 || b["error"] != "server_error" {
		t.Fatalf("session infrastructure failure status %d error %v", status, b["error"])
	}
}
