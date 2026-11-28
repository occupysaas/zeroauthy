package oauth

import (
	"context"
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
