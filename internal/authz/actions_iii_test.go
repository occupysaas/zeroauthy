package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// TestSessionRevokeStopsIssuance (Review Focus 3): api.session.revoke denies
// the login with access_denied, deletes the session and revokes its
// refresh tokens unless preserveRefreshTokens; a later Action's redirect
// does not resurrect it and no code is issued.
func TestSessionRevokeStopsIssuance(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		e := newActionsEnv(t)
		opts := ""
		if preserve {
			opts = ", {preserveRefreshTokens: true}"
		}
		e.actions.Bind(t, e.tenant.ID, actions.TriggerPostLogin,
			e.actions.Deploy(t, e.tenant.ID, actions.TriggerPostLogin, "revoke", `exports.onExecutePostLogin = async (event, api) => { api.session.revoke("risky device"`+opts+`); };`),
			e.actions.Deploy(t, e.tenant.ID, actions.TriggerPostLogin, "later", `exports.onExecutePostLogin = async (event, api) => { api.redirect.sendUserTo("https://example.test/step"); };`))
		ck := e.login(t, fixedNow())
		sess := e.session(t, ck)
		ctx := context.Background()
		rt := &store.RefreshToken{TenantID: e.tenant.ID, ID: "rt_" + sess.ID, UserID: sess.UserID, ClientID: "spa", SessionID: sess.ID, FamilyID: "fam_" + sess.ID, CreatedAt: fixedNow(), ExpiresAt: fixedNow().Add(time.Hour)}
		if err := e.st.RefreshTokens().Create(ctx, rt); err != nil {
			t.Fatal(err)
		}
		q := location(t, e.get(t, goodQuery(), ck)).Query()
		if q.Get("error") != "access_denied" || q.Get("error_description") != "risky device" || q.Get("code") != "" || e.codes != 0 {
			t.Fatalf("query %v codes %d", q, e.codes)
		}
		if _, err := e.st.Sessions().Get(ctx, e.tenant.ID, sess.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("session survives: %v", err)
		}
		got, err := e.st.RefreshTokens().Get(ctx, e.tenant.ID, rt.ID)
		if err != nil {
			t.Fatal(err)
		}
		if (got.RevokedAt == nil) == !preserve {
			t.Fatalf("preserve=%v revoked=%v", preserve, got.RevokedAt)
		}
	}
}

// TestSessionSettersOnlyShorten (Review Focus 1): an expiry later than the
// current one is ignored; an earlier one applies; idle never passes the
// absolute expiry.
func TestSessionSettersOnlyShorten(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.PostLogin(t, e.tenant.ID, "expiry", `exports.onExecutePostLogin = async (event, api) => {
	  const abs = Date.parse(event.session.expires_at);
	  api.session.setExpiresAt(abs - 3600000);
	  api.session.setIdleExpiresAt(abs + 10 * 365 * 86400000);
	};`)
	ck := e.login(t, fixedNow())
	before := e.session(t, ck)
	location(t, e.get(t, goodQuery(), ck))
	after, err := e.st.Sessions().Get(context.Background(), e.tenant.ID, before.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ExpiresAt.Equal(before.ExpiresAt.Add(-time.Hour)) || after.IdleExpiresAt.After(after.ExpiresAt) || after.IdleExpiresAt.After(before.IdleExpiresAt) {
		t.Fatalf("before %v/%v after %v/%v", before.ExpiresAt, before.IdleExpiresAt, after.ExpiresAt, after.IdleExpiresAt)
	}
}

func TestSessionCookieMode(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.PostLogin(t, e.tenant.ID, "mode", `exports.onExecutePostLogin = async (event, api) => { api.session.setCookieMode("non-persistent"); };`)
	ck := e.login(t, fixedNow())
	sess := e.session(t, ck)
	rec := e.get(t, goodQuery(), ck)
	location(t, rec)
	var set string
	for _, h := range rec.Header().Values("Set-Cookie") {
		if strings.HasPrefix(h, "za_session=") {
			set = h
		}
	}
	if set == "" || strings.Contains(strings.ToLower(set), "expires=") || !strings.Contains(set, ck.Value) {
		t.Fatalf("session cookie %q", set)
	}
	if got, _ := e.st.Sessions().Get(context.Background(), e.tenant.ID, sess.ID); got.CookieMode != "non-persistent" {
		t.Fatalf("cookie mode %q", got.CookieMode)
	}
}

func TestSessionMetadataApplied(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.Bind(t, e.tenant.ID, actions.TriggerPostLogin,
		e.actions.Deploy(t, e.tenant.ID, actions.TriggerPostLogin, "md", `exports.onExecutePostLogin = async (event, api) => {
	  api.session.setMetadata("a", "1"); api.session.setMetadata("b", "2"); api.session.deleteMetadata("a");
	};`),
		e.actions.Deploy(t, e.tenant.ID, actions.TriggerPostLogin, "md2", `exports.onExecutePostLogin = async (event, api) => { api.session.evictMetadata(); api.session.setMetadata("c", "3"); };`))
	ck := e.login(t, fixedNow())
	sess := e.session(t, ck)
	if _, err := e.st.Sessions().UpdateMetadata(context.Background(), e.tenant.ID, sess.ID, map[string]string{"old": "x"}); err != nil {
		t.Fatal(err)
	}
	location(t, e.get(t, goodQuery(), ck))
	got, _ := e.st.Sessions().Get(context.Background(), e.tenant.ID, sess.ID)
	if len(got.Metadata) != 1 || got.Metadata["c"] != "3" {
		t.Fatalf("metadata %v", got.Metadata)
	}
}

// primaryUser creates a database user to link into.
func (e *actionsEnv) primaryUser(t *testing.T, id string, blocked bool) {
	t.Helper()
	if err := e.st.Users().Create(context.Background(), &store.User{TenantID: e.tenant.ID, UserID: "auth0|" + id, Email: id + "@acme.test", Blocked: blocked,
		Identities: []store.Identity{{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: id}}, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}); err != nil {
		t.Fatal(err)
	}
}

func (e *actionsEnv) codeUser(t *testing.T, loc *url.URL) string {
	t.Helper()
	ac, err := e.st.AuthCodes().Get(t.Context(), e.tenant.ID, secrets.HashToken(loc.Query().Get("code")))
	if err != nil {
		t.Fatal(err)
	}
	return ac.UserID
}

func TestSetPrimaryUserLinks(t *testing.T) {
	e := newActionsEnv(t)
	e.primaryUser(t, "primary", false)
	e.actions.PostLogin(t, e.tenant.ID, "link", `exports.onExecutePostLogin = async (event, api) => { api.authentication.setPrimaryUser("auth0|primary"); };`)
	ck := e.login(t, fixedNow())
	secondary := e.session(t, ck).UserID
	loc := location(t, e.get(t, goodQuery(), ck))
	if loc.Query().Get("code") == "" || e.codeUser(t, loc) != "auth0|primary" {
		t.Fatalf("redirect %s", loc)
	}
	if _, err := e.st.Users().Get(t.Context(), e.tenant.ID, secondary); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("secondary survives: %v", err)
	}
	p, _ := e.st.Users().Get(t.Context(), e.tenant.ID, "auth0|primary")
	if len(p.Identities) != 2 || p.Identities[1].UserID != strings.TrimPrefix(secondary, "auth0|") {
		t.Fatalf("primary identities %+v", p.Identities)
	}
}

func TestSetPrimaryUserRefusals(t *testing.T) {
	for name, target := range map[string]string{"absent": "auth0|nobody", "blocked": "auth0|blocked", "self": "", "multi": "auth0|primary", "held": "auth0|holder"} {
		t.Run(name, func(t *testing.T) {
			e := newActionsEnv(t)
			e.primaryUser(t, "primary", false)
			e.primaryUser(t, "blocked", true)
			ck := e.login(t, fixedNow())
			secondary := e.session(t, ck).UserID
			if target == "" {
				target = secondary
			}
			ctx := t.Context()
			if name == "multi" || name == "held" {
				u, _ := e.st.Users().Get(ctx, e.tenant.ID, secondary)
				if name == "multi" {
					u.Identities = append(u.Identities, store.Identity{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: "linked77"})
				}
				if err := e.st.Users().Update(ctx, u); err != nil {
					t.Fatal(err)
				}
				if name == "held" {
					own := u.Identities[0]
					// The primary already holds an identity equal to the secondary's.
					if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tenant.ID, UserID: "auth0|holder", Email: "h@acme.test",
						Identities: []store.Identity{{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: "holder"}, {Connection: own.Connection + "-x", Provider: own.Provider, UserID: own.UserID}}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			e.actions.PostLogin(t, e.tenant.ID, "link", `exports.onExecutePostLogin = async (event, api) => { api.authentication.setPrimaryUser(`+strconvQuote(target)+`); };`)
			q := location(t, e.get(t, goodQuery(), ck)).Query()
			if q.Get("error") != "access_denied" || q.Get("code") != "" {
				t.Fatalf("query %v", q)
			}
			if _, err := e.st.Users().Get(ctx, e.tenant.ID, secondary); err != nil {
				t.Fatalf("secondary changed: %v", err)
			}
		})
	}
}

// TestSetPrimaryUserOneWinner (Review Focus 2): two concurrent logins of the
// same secondary linking into different primaries: one links, the other is
// refused (access_denied when it reaches the link, server_error when its
// flow already finds the secondary gone).
func TestSetPrimaryUserOneWinner(t *testing.T) {
	e := newActionsEnv(t)
	e.primaryUser(t, "p1", false)
	e.primaryUser(t, "p2", false)
	e.actions.PostLogin(t, e.tenant.ID, "link", `exports.onExecutePostLogin = async (event, api) => { api.authentication.setPrimaryUser("auth0|" + (event.request.query.login_hint || event.transaction?.login_hint)); };`)
	c1, c2 := e.login(t, fixedNow()), e.login(t, fixedNow())
	type out struct{ q url.Values }
	results := make(chan out, 2)
	for i, ck := range []*http.Cookie{c1, c2} {
		target := []string{"p1", "p2"}[i]
		go func() {
			q := goodQuery()
			q.Set("login_hint", target)
			rec := e.get(t, q, ck)
			u, _ := url.Parse(rec.Header().Get("Location"))
			results <- out{u.Query()}
		}()
	}
	won, refused := 0, 0
	var descs []string
	for range 2 {
		r := <-results
		descs = append(descs, r.q.Get("error_description"))
		switch {
		case r.q.Get("code") != "":
			won++
		case r.q.Get("error") != "":
			refused++
		}
	}
	p1, _ := e.st.Users().Get(t.Context(), e.tenant.ID, "auth0|p1")
	p2, _ := e.st.Users().Get(t.Context(), e.tenant.ID, "auth0|p2")
	if won != 1 || refused != 1 || len(p1.Identities)+len(p2.Identities) != 3 {
		t.Fatalf("won %d refused %d identities %d+%d %v", won, refused, len(p1.Identities), len(p2.Identities), descs)
	}
}

func TestRecordMethod(t *testing.T) {
	e := newActionsEnv(t)
	e.actions.PostLogin(t, e.tenant.ID, "ext", `exports.onExecutePostLogin=(e,a)=>{a.redirect.sendUserTo('https://mfa.test/')};exports.onContinuePostLogin=(e,a)=>{a.authentication.recordMethod('https://mfa.test/factor')};`)
	ck := e.login(t, fixedNow())
	sess := e.session(t, ck)
	loc := location(t, e.get(t, goodQuery(), ck))
	req := httptest.NewRequest("GET", "https://acme.example.test/continue?state="+url.QueryEscape(loc.Query().Get("state")), nil)
	req.AddCookie(ck)
	rec := httptest.NewRecorder()
	e.h.Continue(rec, req.WithContext(tenant.WithResolved(req.Context(), tenant.Resolved{Tenant: e.tenant, Host: "acme.example.test"})))
	loc = location(t, rec)
	ac, err := e.st.AuthCodes().Get(t.Context(), e.tenant.ID, secrets.HashToken(loc.Query().Get("code")))
	if err != nil || ac.MFAAt.IsZero() {
		t.Fatalf("code %+v %v", ac, err)
	}
	got, _ := e.st.Sessions().Get(t.Context(), e.tenant.ID, sess.ID)
	found := false
	for _, m := range got.AuthMethods {
		found = found || m.Name == "https://mfa.test/factor"
	}
	if !found || got.MFAAt.IsZero() {
		t.Fatalf("session methods %+v mfa %v", got.AuthMethods, got.MFAAt)
	}
}

func strconvQuote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func TestUserinfoClaimsClearedWithoutActions(t *testing.T) {
	for name, runtime := range map[string]bool{"no-runtime": false, "no-bindings": true} {
		t.Run(name, func(t *testing.T) {
			e := newActionsEnv(t)
			e.actions.PostLogin(t, e.tenant.ID, "userinfo", `exports.onExecutePostLogin=(event,api)=>api.idToken.setCustomClaim('urn:flow','before');`)
			ck := e.login(t, fixedNow())
			sess := e.session(t, ck)
			location(t, e.get(t, goodQuery(), ck))
			saved, err := e.st.Sessions().Get(t.Context(), e.tenant.ID, sess.ID)
			if err != nil || !strings.Contains(saved.UserinfoClaims["spa"], "before") {
				t.Fatalf("claims=%+v %v", saved, err)
			}
			if runtime {
				e.actions.Bind(t, e.tenant.ID, actions.TriggerPostLogin)
			} else {
				e.h.Actions = nil
			}
			location(t, e.get(t, goodQuery(), ck))
			saved, err = e.st.Sessions().Get(t.Context(), e.tenant.ID, sess.ID)
			if err != nil || strings.Contains(saved.UserinfoClaims["spa"], "before") {
				t.Fatalf("stale claims=%+v %v", saved, err)
			}
		})
	}
}
