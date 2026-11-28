package oauth

import (
	"context"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/actions/actionstest"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
	"time"
)

// TestRefreshTokenSettersOnlyShorten: api.refreshToken setters shorten the
// live refresh token (the successor when it rotates) and never lengthen it
// (LR40-3); metadata calls apply in call order.
func TestRefreshTokenSettersOnlyShorten(t *testing.T) {
	for _, rotating := range []bool{false, true} {
		f := newActionsFixture(t)
		if rotating {
			f.rotating(t)
		}
		f.actions.PostLogin(t, f.tid, "rt", `exports.onExecutePostLogin = async (event, api) => {
		  if (!event.refresh_token) return;
		  api.refreshToken.setExpiresAt(Date.now() + 3600 * 1000);
		  api.refreshToken.setIdleExpiresAt(Date.now() + 100 * 365 * 86400 * 1000);
		  api.refreshToken.setMetadata("device", "tv");
		  api.refreshToken.setMetadata("gone", "x");
		  api.refreshToken.deleteMetadata("gone");
		};`)
		status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid offline_access read:things"))
		if status != 200 {
			t.Fatalf("password: %d %v", status, body)
		}
		raw := body["refresh_token"].(string)
		before := f.storedRT(t, raw)
		status, body = f.token(t, refreshForm("ropg", raw, "client_secret", "ropg-secret"))
		if status != 200 {
			t.Fatalf("refresh: %d %v", status, body)
		}
		live := before
		if next, ok := body["refresh_token"].(string); ok && next != raw {
			live = f.storedRT(t, next)
		} else {
			live = f.storedRT(t, raw)
		}
		if live.ExpiresAt.IsZero() || live.ExpiresAt.After(time.Now().Add(61*time.Minute)) {
			t.Fatalf("rotating=%v expires %v", rotating, live.ExpiresAt)
		}
		if !live.IdleExpiresAt.IsZero() && live.IdleExpiresAt.After(live.ExpiresAt) {
			t.Fatalf("rotating=%v idle %v past absolute %v", rotating, live.IdleExpiresAt, live.ExpiresAt)
		}
		if live.Metadata["device"] != "tv" || len(live.Metadata) != 1 {
			t.Fatalf("rotating=%v metadata %v", rotating, live.Metadata)
		}
	}
}

// TestRefreshSessionRevoke: api.session.revoke on a refresh exchange with a
// session ends that session and refuses the exchange.
func TestRefreshSessionRevoke(t *testing.T) {
	f := newActionsFixture(t)
	f.actions.PostLogin(t, f.tid, "rev", `exports.onExecutePostLogin = async (event, api) => {
	  if (event.refresh_token && event.session) api.session.revoke("stolen device");
	};`)
	code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
	status, body := f.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatalf("code: %d %v", status, body)
	}
	raw := body["refresh_token"].(string)
	rt := f.storedRT(t, raw)
	if rt.SessionID == "" {
		t.Fatal("refresh family is not bound to a session")
	}
	status, body = f.token(t, refreshForm("rt-spa", raw))
	if status == 200 || body["error"] != "access_denied" {
		t.Fatalf("refresh after revoke: %d %v", status, body)
	}
	if _, err := f.st.Sessions().Get(context.Background(), f.tid, rt.SessionID); err == nil {
		t.Fatal("session survives api.session.revoke")
	}
}

// TestSetPrimaryUserTokenGrantRefused: account linking from an Action runs
// only in the browser flow; a token grant asking for it is refused rather
// than silently issuing for the secondary.
func TestSetPrimaryUserTokenGrantRefused(t *testing.T) {
	f := newActionsFixture(t)
	f.actions.PostLogin(t, f.tid, "link", `exports.onExecutePostLogin = async (event, api) => { api.authentication.setPrimaryUser("auth0|someone"); };`)
	status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "audience", acmeAPI, "scope", "openid"))
	if status != 403 || body["error"] != "access_denied" {
		t.Fatalf("password grant: %d %v", status, body)
	}
}

func TestUserinfoClaimsAfterRefresh(t *testing.T) {
	f := newActionsFixture(t)
	f.actions.PostLogin(t, f.tid, "claims", `exports.onExecutePostLogin=(event,api)=>{api.idToken.setCustomClaim("https://app.test/flow",event.refresh_token ? "refresh" : "login");};`)
	code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
	status, body := f.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	raw := body["refresh_token"].(string)
	rt := f.storedRT(t, raw)
	s, err := f.st.Sessions().Get(context.Background(), f.tid, rt.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.UserinfoClaims["rt-spa"], `"login"`) {
		t.Fatalf("login claims: %v", s.UserinfoClaims)
	}
	status, body = f.token(t, refreshForm("rt-spa", raw))
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	s, err = f.st.Sessions().Get(context.Background(), f.tid, rt.SessionID)
	if err != nil || !strings.Contains(s.UserinfoClaims["rt-spa"], `"refresh"`) {
		t.Fatalf("refresh claims: %+v %v", s, err)
	}
	var claims map[string]any
	if err = f.keys.Verify(context.Background(), f.tid, body["access_token"].(string), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sid"] != rt.SessionID {
		t.Fatalf("access token lacks sid: %v", claims["sid"])
	}
}

func TestLinkedTokensUseFinalSubjectPermissions(t *testing.T) {
	f := newActionsFixture(t)
	ctx := t.Context()
	f.setRBAC(t, true)
	api, err := f.st.ResourceServers().GetByIdentifier(ctx, f.tid, acmeAPI)
	if err != nil {
		t.Fatal(err)
	}
	api.TokenDialect = "access_token_authz"
	if err = f.st.ResourceServers().Update(ctx, api); err != nil {
		t.Fatal(err)
	}
	primary := &store.User{TenantID: f.tid, UserID: "auth0|primary", Email: "primary@acme.test", Identities: []store.Identity{{Provider: "auth0", Connection: "Username-Password-Authentication", UserID: "primary"}}, CreatedAt: fixedNow(), UpdatedAt: fixedNow()}
	if err := f.st.Users().Create(ctx, primary); err != nil {
		t.Fatal(err)
	}
	for uid, permission := range map[string]string{f.aliceID(t): "write:things", primary.UserID: "read:things"} {
		if err := f.st.RBAC().ChangeUserPermissions(ctx, f.tid, uid, true, []store.PermissionKey{{ResourceServerIdentifier: acmeAPI, PermissionName: permission}}); err != nil {
			t.Fatal(err)
		}
	}
	f.actions.PostLogin(t, f.tid, "link-rbac", `exports.onExecutePostLogin=(event,api)=>api.authentication.setPrimaryUser('auth0|primary');`)
	code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
	status, body := f.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	claims, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if claims["sub"] != primary.UserID || fmt.Sprint(claims["permissions"]) != "[read:things]" {
		t.Fatalf("final authorization sub=%v permissions=%v", claims["sub"], claims["permissions"])
	}
}

func TestOnlineRefreshActionEffects(t *testing.T) {
	f, s := onlineFixture(t, true, "persistent", false)
	a := actionstest.New(t, f.st, f.wrapper)
	f.h.Actions = a.Engine
	a.PostLogin(t, s.TenantID, "online-effects", `exports.onExecutePostLogin=(e,a)=>{if(!e.refresh_token)return;a.refreshToken.setMetadata('device','tv');a.refreshToken.setExpiresAt(Date.parse(e.session.expires_at)-3600000);a.refreshToken.setIdleExpiresAt(Date.parse(e.session.idle_expires_at)-600000);a.session.setIdleExpiresAt(Date.parse(e.session.idle_expires_at)-600000);};`)
	status, body := issueOnline(t, f)
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	raw := body["refresh_token"].(string)
	status, body = refreshOnline(t, f, raw)
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	rt := f.storedRT(t, raw)
	if rt.Metadata["device"] != "tv" || !rt.ExpiresAt.Equal(s.ExpiresAt.Add(-time.Hour)) || !rt.IdleExpiresAt.Equal(s.IdleExpiresAt.Add(-10*time.Minute)) {
		t.Fatalf("token effects lost: %+v", rt)
	}
	after, err := f.st.Sessions().Get(t.Context(), s.TenantID, s.ID)
	if err != nil || !after.IdleExpiresAt.Equal(s.IdleExpiresAt.Add(-10*time.Minute)) {
		t.Fatalf("session cap overwritten: %+v %v", after, err)
	}
}

type changedRefreshUserStore struct{ store.Store }

func (s changedRefreshUserStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(changedRefreshUserStore{tx}) })
}
func (s changedRefreshUserStore) Users() store.Users { return changedRefreshUsers{s.Store.Users()} }

type changedRefreshUsers struct{ store.Users }

func (u changedRefreshUsers) GetForUpdate(ctx context.Context, tid, id string) (*store.User, error) {
	v, e := u.Users.GetForUpdate(ctx, tid, id)
	if e == nil {
		v.Version++
	}
	return v, e
}
func TestRefusedRefreshDoesNotPersistSessionEffects(t *testing.T) {
	f := newActionsFixture(t)
	code := f.authorize(t, "rt-spa", "https://rt.acme.test/cb", acmeUserScopes)
	status, body := f.token(t, codeForm(code, "rt-spa", "https://rt.acme.test/cb", pkceVerifier))
	if status != 200 {
		t.Fatal(status, body)
	}
	raw := body["refresh_token"].(string)
	rt := f.storedRT(t, raw)
	f.actions.PostLogin(t, f.tid, "refused-session", `exports.onExecutePostLogin=(e,a)=>{a.session.setMetadata('should-not-commit','v');a.idToken.setCustomClaim('urn:refused',true);};`)
	f.h.Store = changedRefreshUserStore{f.st}
	status, body = f.token(t, refreshForm("rt-spa", raw))
	if status == 200 {
		t.Fatal("version race accepted")
	}
	after, err := f.st.Sessions().Get(t.Context(), f.tid, rt.SessionID)
	if err != nil || after.Metadata["should-not-commit"] != "" || strings.Contains(after.UserinfoClaims["rt-spa"], "refused") {
		t.Fatalf("refused writes persisted %+v %v", after, err)
	}
}
