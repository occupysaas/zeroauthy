package authz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
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
