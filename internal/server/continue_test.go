package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestActionsRedirectContinueHosts(t *testing.T) {
	var ae *actionstest.Env
	var sm *session.Manager
	e := newFlowEnvSeed(t, flowSeed, func(d *Deps) { ae = actionstest.New(t, d.Store, d.Wrapper); d.Actions = ae.Engine; sm = d.Sessions })
	ctx := context.Background()
	tn, err := e.st.Tenants().GetByName(ctx, "flow")
	if err != nil {
		t.Fatal(err)
	}
	tn.Domains = append(tn.Domains, "login.flow.test")
	if err = e.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	ae.PostLogin(t, tn.ID, "redirect", `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.test/');exports.onContinuePostLogin=(e,a)=>{if(e.request.query.answer!=='yes')throw Error('no answer')};`)
	user, err := e.st.Users().FindByLogin(ctx, tn.ID, "Username-Password-Authentication", "alice@flow.test")
	if err != nil {
		t.Fatal(err)
	}
	canonical := strings.TrimPrefix(e.base, "https://")
	for _, host := range []string{canonical, "login.flow.test"} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(host+"/"+method, func(t *testing.T) {
				res := tenant.Resolved{Tenant: tn, Host: host}
				start := httptest.NewRequest("GET", "https://"+host+"/", nil)
				start = start.WithContext(tenant.WithResolved(ctx, res))
				rec := httptest.NewRecorder()
				if _, err := sm.Start(ctx, rec, start, tn, user.UserID, "Username-Password-Authentication", time.Now()); err != nil {
					t.Fatal(err)
				}
				cookie := rec.Result().Cookies()[0]
				req := httptest.NewRequest("GET", authorizeURL("https://"+host), nil)
				req.AddCookie(cookie)
				rec = httptest.NewRecorder()
				e.srv.Config.Handler.ServeHTTP(rec, req)
				loc, err := url.Parse(rec.Header().Get("Location"))
				if err != nil || loc.Host != "step.test" || loc.Query().Get("state") == "" {
					t.Fatalf("authorize status=%d location=%v body=%s", rec.Code, loc, rec.Body)
				}
				target := "https://" + host + "/continue?answer=yes"
				form := ""
				if method == "POST" {
					form = url.Values{"state": {loc.Query().Get("state")}}.Encode()
				} else {
					target += "&state=" + url.QueryEscape(loc.Query().Get("state"))
				}
				req = httptest.NewRequest(method, target, strings.NewReader(form))
				if method == "POST" {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				req.AddCookie(cookie)
				rec = httptest.NewRecorder()
				e.srv.Config.Handler.ServeHTTP(rec, req)
				loc, err = url.Parse(rec.Header().Get("Location"))
				if err != nil || rec.Code != http.StatusFound || loc.Host != "app.flow.test" || loc.Query().Get("code") == "" {
					t.Fatalf("continue status=%d location=%v body=%s", rec.Code, loc, rec.Body)
				}
			})
		}
	}
}
