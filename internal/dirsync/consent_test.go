package dirsync

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type consentEnv struct {
	*env
	c       *Consent
	cookies []*http.Cookie
}

func newConsentEnv(t *testing.T) *consentEnv {
	e := newEnv(t, "", true)
	// No grant yet.
	p, _ := e.st.DirectorySync().GetProvisioning(context.Background(), "ten_a", "con_ws")
	p.AdminGrant = nil
	_ = e.st.DirectorySync().UpdateProvisioning(context.Background(), p)
	return &consentEnv{env: e, c: &Consent{Store: e.st, Wrapper: e.w, Providers: e.dir.providers(), Now: func() time.Time { return e.now }}}
}

func (ce *consentEnv) get(t *testing.T, tid, target string) *httptest.ResponseRecorder {
	t.Helper()
	tn, err := ce.st.Tenants().Get(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://"+tn.Name+".example.test"+target, nil)
	for _, c := range ce.cookies {
		r.AddCookie(c)
	}
	r = r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: tn.Name + ".example.test"}))
	rec := httptest.NewRecorder()
	ce.c.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 && c.Value != "" {
			ce.cookies = []*http.Cookie{c}
		}
	}
	return rec
}

// consent runs the start and plays the administrator at the fixture.
func (ce *consentEnv) consent(t *testing.T, ticket string) *httptest.ResponseRecorder {
	t.Helper()
	rec := ce.get(t, "ten_a", ConsentPath+"?ticket="+url.QueryEscape(ticket))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	u, _ := url.Parse(rec.Header().Get("Location"))
	q := u.Query()
	if !strings.HasPrefix(u.String(), ce.dir.srv.URL+"/authorize?") || q.Get("access_type") != "offline" || q.Get("prompt") != "consent" ||
		q.Get("hd") != "corp.example.com" || !strings.Contains(q.Get("scope"), rules.DirectoryUserScope) || !strings.Contains(q.Get("scope"), rules.DirectoryGroupScope) ||
		q.Get("redirect_uri") != "https://a.example.test"+CallbackPath || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize %s", u)
	}
	ce.dir.mu.Lock()
	ce.dir.codes["code-1"] = q.Get("nonce")
	ce.dir.mu.Unlock()
	return ce.get(t, "ten_a", CallbackPath+"?"+url.Values{"code": {"code-1"}, "state": {q.Get("state")}}.Encode())
}

func (ce *consentEnv) provisioning(t *testing.T) *store.DirectoryProvisioning {
	p, err := ce.st.DirectorySync().GetProvisioning(context.Background(), "ten_a", "con_ws")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConsent(t *testing.T) {
	ce := newConsentEnv(t)
	ticket, err := NewTicket(ce.w, "ten_a", "con_ws", ce.now)
	if err != nil {
		t.Fatal(err)
	}
	rec := ce.consent(t, ticket)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Directory access granted") {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body)
	}
	p := ce.provisioning(t)
	if len(p.AdminGrant) == 0 || bytes.Contains(p.AdminGrant, []byte(adminRefresh)) || p.NextSyncAt == nil || p.SyncID == "" {
		t.Fatalf("grant not stored sealed or no sync scheduled: %+v", p)
	}
	if got, err := OpenGrant(ce.w, "ten_a", "con_ws", p.AdminGrant); err != nil || got != adminRefresh {
		t.Fatalf("grant %q %v", got, err)
	}
	// Sealed to the connection: another connection cannot open it.
	if _, err := OpenGrant(ce.w, "ten_a", "con_other", p.AdminGrant); err == nil {
		t.Fatal("grant opened for another connection")
	}
	if strings.Contains(rec.Body.String(), adminRefresh) || strings.Contains(rec.Body.String(), adminAccess) {
		t.Fatal("page exposes a token")
	}
}

func TestConsentRefusals(t *testing.T) {
	for name, tc := range map[string]func(ce *consentEnv) (status int, ticket string){
		"another tenant's ticket": func(ce *consentEnv) (int, string) {
			tk, _ := NewTicket(ce.w, "ten_b", "con_ws", ce.now)
			return 400, tk
		},
		"expired ticket": func(ce *consentEnv) (int, string) {
			tk, _ := NewTicket(ce.w, "ten_a", "con_ws", ce.now.Add(-TicketTTL-time.Second))
			return 400, tk
		},
		"forged ticket": func(ce *consentEnv) (int, string) { return 400, "AAAA" },
	} {
		t.Run(name, func(t *testing.T) {
			ce := newConsentEnv(t)
			status, tk := tc(ce)
			if rec := ce.get(t, "ten_a", ConsentPath+"?ticket="+url.QueryEscape(tk)); rec.Code != status {
				t.Fatalf("start = %d", rec.Code)
			}
		})
	}
	for name, tc := range map[string]struct {
		setup  func(ce *consentEnv)
		status int
	}{
		"not an administrator":      {func(ce *consentEnv) { ce.dir.forbidden = true }, 403},
		"account of another domain": {func(ce *consentEnv) { ce.dir.idClaims["hd"] = "evil.example.com" }, 400},
		"no offline access":         {func(ce *consentEnv) { ce.dir.refresh = "" }, 400},
	} {
		t.Run(name, func(t *testing.T) {
			ce := newConsentEnv(t)
			tc.setup(ce)
			tk, _ := NewTicket(ce.w, "ten_a", "con_ws", ce.now)
			if rec := ce.consent(t, tk); rec.Code != tc.status {
				t.Fatalf("callback = %d %s", rec.Code, rec.Body)
			}
			if p := ce.provisioning(t); len(p.AdminGrant) != 0 {
				t.Fatal("grant stored")
			}
		})
	}
	t.Run("state from another browser", func(t *testing.T) {
		ce := newConsentEnv(t)
		tk, _ := NewTicket(ce.w, "ten_a", "con_ws", ce.now)
		rec := ce.get(t, "ten_a", ConsentPath+"?ticket="+url.QueryEscape(tk))
		u, _ := url.Parse(rec.Header().Get("Location"))
		ce.dir.codes["code-1"] = u.Query().Get("nonce")
		ce.cookies = nil
		if rec := ce.get(t, "ten_a", CallbackPath+"?"+url.Values{"code": {"code-1"}, "state": {u.Query().Get("state")}}.Encode()); rec.Code != 400 {
			t.Fatalf("callback without the attempt cookie = %d", rec.Code)
		}
		if p := ce.provisioning(t); len(p.AdminGrant) != 0 {
			t.Fatal("grant stored")
		}
	})
	t.Run("forged state", func(t *testing.T) {
		ce := newConsentEnv(t)
		tk, _ := NewTicket(ce.w, "ten_a", "con_ws", ce.now)
		rec := ce.get(t, "ten_a", ConsentPath+"?ticket="+url.QueryEscape(tk))
		u, _ := url.Parse(rec.Header().Get("Location"))
		// A valid code: only the state binding refuses the callback.
		ce.dir.codes["code-1"] = u.Query().Get("nonce")
		if rec := ce.get(t, "ten_a", CallbackPath+"?code=code-1&state=forged"); rec.Code != 400 {
			t.Fatalf("forged state = %d", rec.Code)
		}
		if p := ce.provisioning(t); len(p.AdminGrant) != 0 {
			t.Fatal("grant stored")
		}
	})
}
