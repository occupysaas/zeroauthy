package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestActionsRedirectRoundTrip(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		t.Run(method, func(t *testing.T) {
			e := newActionsEnv(t)
			e.actions.PostLogin(t, e.tenant.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>{a.idToken.setCustomClaim('before',1);a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/',{query:{a:'1'}})};exports.onContinuePostLogin=(e,a)=>{if(e.request.query.answer!=='yes')throw Error('query');if(e.request.method==='POST'&&e.request.body.extra!=='posted')throw Error('body');a.idToken.setCustomClaim('after',2)};`)
			cookie := e.login(t, fixedNow())
			loc := location(t, e.get(t, goodQuery(), cookie))
			if loc.Host != "step.test" || loc.Query().Get("a") != "1" || loc.Query().Get("state") == "" || e.codes != 0 {
				t.Fatalf("redirect %s codes=%d", loc, e.codes)
			}
			var req *http.Request
			target := "https://acme.example.test/continue?" + url.Values{"state": {loc.Query().Get("state")}, "answer": {"yes"}}.Encode()
			if method == "POST" {
				req = httptest.NewRequest(method, target, strings.NewReader("extra=posted"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				req = httptest.NewRequest(method, target, nil)
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			e.h.Continue(rec, req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"})))
			loc = location(t, rec)
			if loc.Host != "app.acme.test" || loc.Query().Get("code") == "" || e.codes != 1 {
				t.Fatalf("completed %s codes=%d", loc, e.codes)
			}
			ac, err := e.st.AuthCodes().Consume(context.Background(), e.tenant.ID, secrets.HashToken(loc.Query().Get("code")), fixedNow())
			if err != nil {
				t.Fatal(err)
			}
			eff, err := actions.OpenEffects(e.w, e.tenant.ID, actions.SealCode, ac.ActionEffects, ac.CodeHash)
			if err != nil || eff.IDClaims["before"] != float64(1) || eff.IDClaims["after"] != float64(2) {
				b, _ := json.Marshal(eff)
				t.Fatalf("effects %s %v", b, err)
			}
		})
	}
}
func TestActionsContinueRejects(t *testing.T) {
	t.Run("prompt none requires interaction", func(t *testing.T) {
		e := newActionsEnv(t)
		e.postLogin(t, "redirect", `api.redirect.sendUserTo('https://step.test/');`)
		q := goodQuery()
		q.Set("prompt", "none")
		loc := location(t, e.get(t, q, e.login(t, fixedNow())))
		if loc.Query().Get("error") != "interaction_required" || e.codes != 0 {
			t.Fatalf("%s codes=%d", loc, e.codes)
		}
	})
}

func TestActionsContinueHTTPRejects(t *testing.T) {
	for _, tc := range []string{"missing", "wrong", "expired", "replayed", "no-cookie", "other-session", "other-tenant", "other-origin", "duplicate-query", "duplicate-body", "conflicting-state", "wrong-content-type", "oversized-body", "blocked-user", "deleted-client", "disabled-connection"} {
		t.Run(tc, func(t *testing.T) {
			e := newActionsEnv(t)
			e.actions.Engine.Now = fixedNow
			e.actions.PostLogin(t, e.tenant.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=()=>{};`)
			cookie := e.login(t, fixedNow())
			loc := location(t, e.get(t, goodQuery(), cookie))
			state := loc.Query().Get("state")
			res := tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"}
			method, body := "GET", ""
			ct := "application/x-www-form-urlencoded"
			switch tc {
			case "missing":
				state = ""
			case "wrong":
				state = "invalid"
			case "expired":
				e.actions.Engine.Now = func() time.Time { return fixedNow().Add(15 * time.Minute) }
			case "no-cookie":
				cookie = nil
			case "other-session":
				cookie = e.login(t, fixedNow())
			case "other-tenant":
				tn, err := e.st.Tenants().GetByName(context.Background(), "globex")
				if err != nil {
					t.Fatal(err)
				}
				res = tenant.Resolved{Tenant: tn, Host: "globex.example.test"}
			case "other-origin":
				res.Host = "custom.acme.test"
			case "duplicate-body":
				method = "POST"
				body = "state=x&state=y"
			case "conflicting-state":
				method = "POST"
				body = "state=other"
			case "wrong-content-type":
				method = "POST"
				ct = "application/json"
				body = "{}"
			case "oversized-body":
				method = "POST"
				body = "large=" + strings.Repeat("x", 65<<10)
			case "blocked-user":
				u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
				if err != nil {
					t.Fatal(err)
				}
				u.Blocked = true
				if err = e.st.Users().Update(context.Background(), u); err != nil {
					t.Fatal(err)
				}
			case "deleted-client":
				if err := e.st.Clients().Delete(context.Background(), e.tenant.ID, "spa"); err != nil {
					t.Fatal(err)
				}
			case "disabled-connection":
				c, err := e.st.Connections().GetByName(context.Background(), e.tenant.ID, "Username-Password-Authentication")
				if err != nil {
					t.Fatal(err)
				}
				c.EnabledClients = nil
				c.IsDomainConnection = false
				if err = e.st.Connections().Update(context.Background(), c); err != nil {
					t.Fatal(err)
				}
			}
			target := "https://" + res.Host + "/continue?state=" + url.QueryEscape(state)
			if tc == "duplicate-query" {
				target += "&state=x"
			}
			req := httptest.NewRequest(method, target, strings.NewReader(body))
			if method == "POST" {
				req.Header.Set("Content-Type", ct)
			}
			if cookie != nil {
				req.AddCookie(cookie)
			}
			req = req.WithContext(tenant.WithResolved(req.Context(), res))
			rec := httptest.NewRecorder()
			baselineCodes := 0
			if tc == "replayed" {
				e.h.Continue(rec, req)
				if rec.Code != http.StatusFound || e.codes != 1 {
					t.Fatalf("initial continuation status=%d codes=%d", rec.Code, e.codes)
				}
				baselineCodes = 1
				rec = httptest.NewRecorder()
			}
			e.h.Continue(rec, req)
			if rec.Code != http.StatusBadRequest || e.codes != baselineCodes || rec.Header().Get("Location") != "" {
				t.Fatalf("rejected status=%d codes=%d Location=%s body=%s", rec.Code, e.codes, rec.Header().Get("Location"), rec.Body)
			}
			if tc != "deleted-client" && tc != "disabled-connection" {
				var b map[string]any
				if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil || b["error"] != "invalid_request" {
					t.Fatalf("error=%s %v", rec.Body, err)
				}
			}
		})
	}
}
func TestActionsContinueDenialAndFailure(t *testing.T) {
	for _, tc := range []string{"deny", "throw"} {
		t.Run(tc, func(t *testing.T) {
			e := newActionsEnv(t)
			body := `a.access.deny('not today')`
			if tc == "throw" {
				body = `throw Error('private details')`
			}
			e.actions.PostLogin(t, e.tenant.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>{`+body+`};`)
			cookie := e.login(t, fixedNow())
			state := location(t, e.get(t, goodQuery(), cookie)).Query().Get("state")
			req := httptest.NewRequest("GET", "https://acme.example.test/continue?state="+state, nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			e.h.Continue(rec, req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"})))
			loc := location(t, rec)
			want := "access_denied"
			if tc == "throw" {
				want = "server_error"
			}
			if loc.Host != "app.acme.test" || loc.Query().Get("error") != want || e.codes != 0 {
				t.Fatalf("location=%s codes=%d", loc, e.codes)
			}
			u, err := e.st.Users().FindByLogin(context.Background(), e.tenant.ID, "Username-Password-Authentication", "alice@acme.test")
			if err != nil {
				t.Fatal(err)
			}
			if (u.AppMetadata["held"] == true) != (tc == "deny") {
				t.Fatalf("metadata=%v", u.AppMetadata)
			}
		})
	}
}

func TestActionsContinueBeforeConsent(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.PostLogin(t, e.tenant.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('runs',1);a.idToken.setCustomClaim('before',1);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>{a.idToken.setCustomClaim('after',2)};`)
	cookie := e.login(t, fixedNow())
	state := location(t, e.get(t, partnerQuery(), cookie)).Query().Get("state")
	req := httptest.NewRequest("GET", "https://acme.example.test/continue?state="+state, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.h.Continue(rec, req.WithContext(tenant.WithResolved(req.Context(), e.res())))
	loc := location(t, rec)
	if loc.Path != "/u/consent" || e.codes != 0 || e.runs(t) != 1 {
		t.Fatalf("location=%s codes=%d runs=%v", loc, e.codes, e.runs(t))
	}
	txn, err := e.st.AuthTransactions().Get(context.Background(), e.tenant.ID, loc.Query().Get("state"))
	if err != nil {
		t.Fatal(err)
	}
	loc = location(t, e.consent(t, txn, cookie, true))
	if loc.Host != "partner.example" || loc.Query().Get("code") == "" || e.runs(t) != 1 {
		t.Fatalf("consent reran Actions: %s runs=%v", loc, e.runs(t))
	}
	ac, err := e.st.AuthCodes().Get(context.Background(), e.tenant.ID, secrets.HashToken(loc.Query().Get("code")))
	if err != nil {
		t.Fatal(err)
	}
	eff, err := actions.OpenEffects(e.w, e.tenant.ID, actions.SealCode, ac.ActionEffects, ac.CodeHash)
	if err != nil || eff.IDClaims["before"] != float64(1) || eff.IDClaims["after"] != float64(2) {
		t.Fatalf("consent lost effects: %+v %v", eff, err)
	}
}
