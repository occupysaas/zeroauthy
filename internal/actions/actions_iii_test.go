package actions_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (h *harness) runLogin(t *testing.T, body string, edit func(*actions.PostLoginInput)) (*actions.Result, error) {
	t.Helper()
	a := h.action("t1", trigLogin, "iii", "exports.onExecutePostLogin = async (event, api) => {\n"+body+"\n};", nil, false)
	h.bind("t1", trigLogin, a)
	in := h.loginInput("t1")
	in.Session = &store.LoginSession{TenantID: "t1", ID: "sess-1", UserID: "auth0|u1", Metadata: map[string]string{"old": "x"},
		ExpiresAt: h.now.Add(72 * time.Hour), IdleExpiresAt: h.now.Add(24 * time.Hour), CreatedAt: h.now, AuthenticatedAt: h.now}
	if edit != nil {
		edit(&in)
	}
	return h.eng.PostLogin(t.Context(), in)
}

func accepted(r *actions.Result, err error) bool { return err == nil && r != nil && r.Denied == nil }

// TestPreludeSessionMethods: api.session calls are recorded in call order;
// invalid arguments fail the flow.
func TestPreludeSessionMethods(t *testing.T) {
	h := newHarness(t)
	abs := h.now.Add(2 * time.Hour).UnixMilli()
	idle := h.now.Add(time.Hour).UnixMilli()
	r, err := h.runLogin(t, `api.session.setExpiresAt(`+itoa(abs)+`);
	  api.session.setIdleExpiresAt(`+itoa(idle)+`);
	  api.session.setCookieMode('non-persistent');
	  api.session.setMetadata('a', '1');
	  api.session.deleteMetadata('old');
	  api.session.evictMetadata();
	  api.session.setMetadata('c', '2');
	  api.session.revoke('bad device', {preserveRefreshTokens: true});`, nil)
	if !accepted(r, err) || r.Effects.Session == nil {
		t.Fatalf("result %+v %v", r, err)
	}
	s := r.Effects.Session
	if s.ExpiresAt == nil || s.ExpiresAt.UnixMilli() != abs || s.IdleExpiresAt == nil || s.IdleExpiresAt.UnixMilli() != idle || s.CookieMode != "non-persistent" {
		t.Fatalf("session effects %+v", s)
	}
	ops := []string{}
	for _, op := range s.Metadata {
		ops = append(ops, op.Op+":"+op.Key+"="+op.Value)
	}
	if strings.Join(ops, ",") != "set:a=1,delete:old=,evict:=,set:c=2" {
		t.Fatalf("metadata ops %v", ops)
	}
	if s.Revoke == nil || s.Revoke.Reason != "bad device" || !s.Revoke.PreserveRefreshTokens {
		t.Fatalf("revoke %+v", s.Revoke)
	}
	for name, body := range map[string]string{
		"cookie mode":       `api.session.setCookieMode('forever');`,
		"negative time":     `api.session.setExpiresAt(-1);`,
		"string time":       `api.session.setIdleExpiresAt('soon');`,
		"value not string":  `api.session.setMetadata('k', 5);`,
		"long key":          `api.session.setMetadata('` + strings.Repeat("k", 256) + `', 'v');`,
		"long value":        `api.session.setMetadata('k', '` + strings.Repeat("v", 256) + `');`,
		"26th key":          `for (let i = 0; i < 25; i++) api.session.setMetadata('k' + i, 'v');`,
		"reason not string": `api.session.revoke(5);`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			if r, err := h.runLogin(t, body, nil); accepted(r, err) {
				t.Fatalf("accepted: %+v", r.Effects.Session)
			}
		})
	}
	// 24 new keys beside the stored one is within the limit.
	if r, err := newHarness(t).runLogin(t, `for (let i = 0; i < 24; i++) api.session.setMetadata('k' + i, 'v');`, nil); !accepted(r, err) {
		t.Fatalf("25 keys refused: %v", err)
	}
}

// TestPreludeRefreshTokenAbsent: api.refreshToken is undefined without
// event.refresh_token (X4) and records its calls on a refresh exchange.
func TestPreludeRefreshTokenAbsent(t *testing.T) {
	h := newHarness(t)
	r, err := h.runLogin(t, `api.idToken.setCustomClaim('https://x.test/rt', typeof api.refreshToken);`, nil)
	if !accepted(r, err) || r.Effects.IDClaims["https://x.test/rt"] != "undefined" {
		t.Fatalf("without refresh token: %+v %v", r, err)
	}
	h = newHarness(t)
	until := h.now.Add(time.Hour).UnixMilli()
	r, err = h.runLogin(t, `api.refreshToken.setExpiresAt(`+itoa(until)+`); api.refreshToken.setIdleExpiresAt(`+itoa(until)+`); api.refreshToken.setMetadata('device', 'tv'); api.refreshToken.deleteMetadata('x'); api.refreshToken.evictMetadata();`,
		func(in *actions.PostLoginInput) {
			in.RefreshToken = &store.RefreshToken{TenantID: "t1", ID: "rt-1", UserID: "auth0|u1", ClientID: "cli1", Metadata: map[string]string{}}
		})
	if !accepted(r, err) || r.Effects.RefreshToken == nil || r.Effects.RefreshToken.ExpiresAt.UnixMilli() != until || len(r.Effects.RefreshToken.Metadata) != 3 {
		t.Fatalf("refresh effects %+v %v", r, err)
	}
}

func TestPreludeRecordMethodOnlyInContinue(t *testing.T) {
	h := newHarness(t)
	if r, err := h.runLogin(t, `api.authentication.recordMethod('https://mfa.example.test/factor');`, nil); accepted(r, err) {
		t.Fatal("recordMethod accepted in onExecutePostLogin")
	}
}

func TestPreludeSetPrimaryUser(t *testing.T) {
	h := newHarness(t)
	r, err := h.runLogin(t, `api.authentication.setPrimaryUser('auth0|first'); api.authentication.setPrimaryUser('auth0|primary');`, nil)
	if !accepted(r, err) || r.Effects.PrimaryUserID != "auth0|primary" {
		t.Fatalf("result %+v %v", r, err)
	}
	for _, body := range []string{`api.authentication.setPrimaryUser(5);`, `api.authentication.setPrimaryUser('');`} {
		if r, err := newHarness(t).runLogin(t, body, nil); accepted(r, err) {
			t.Fatalf("%s accepted", body)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestPreludeSetUserId(t *testing.T) {
	for _, tc := range []struct {
		code string
		ok   bool
	}{{`api.user.setUserId('external')`, true}, {`api.user.setUserId(42)`, false}, {`api.user.setUserId('')`, false}, {`api.user.setUserId('with space')`, false}, {`api.user.setUserId('x'.repeat(256))`, false}} {
		h := newHarness(t)
		a := h.action("t1", actions.TriggerPreUserRegistration, "custom-id", `exports.onExecutePreUserRegistration=(event,api)=>{`+tc.code+`};`, nil, false)
		h.bind("t1", actions.TriggerPreUserRegistration, a)
		login := h.loginInput("t1")
		in := actions.RegistrationInput{Tenant: login.Tenant, User: login.User, Connection: &store.Connection{Strategy: store.StrategyDatabase}}
		r, err := h.eng.PreUserRegistration(context.Background(), in)
		if tc.ok {
			if err != nil || r.Effects.SignupUserID != "external" {
				t.Fatalf("%+v %v", r, err)
			}
		} else if err == nil {
			t.Fatalf("accepted %s", tc.code)
		}
	}
}

func TestActionEffectNamesRecorded(t *testing.T) {
	h := newHarness(t)
	r, err := h.runLogin(t, `api.session.setCookieMode('non-persistent');api.authentication.setPrimaryUser('auth0|primary');`, nil)
	if err != nil {
		t.Fatal(err)
	}
	ex := h.execution("t1", r.ExecutionID)
	if strings.Join(ex.Results[0].RequestedEffects, ",") != "session.setCookieMode,authentication.setPrimaryUser" {
		t.Fatalf("effects=%v", ex.Results[0].RequestedEffects)
	}
}

func TestMetadataKeyBudgetAcrossActions(t *testing.T) {
	h := newHarness(t)
	first := h.action("t1", trigLogin, "delete-key", `exports.onExecutePostLogin=(e,a)=>{a.session.deleteMetadata('k0');a.refreshToken.deleteMetadata('k0');};`, nil, false)
	second := h.action("t1", trigLogin, "replace-key", `exports.onExecutePostLogin=(e,a)=>{a.session.setMetadata('replacement','v');a.refreshToken.setMetadata('replacement','v');};`, nil, false)
	h.bind("t1", trigLogin, first, second)
	in := h.loginInput("t1")
	md := map[string]string{}
	for i := range 25 {
		md[fmt.Sprint("k", i)] = "v"
	}
	in.Session = &store.LoginSession{ID: "s", UserID: in.User.UserID, Metadata: md}
	in.RefreshToken = &store.RefreshToken{ID: "rt", Metadata: md}
	r, err := h.eng.PostLogin(context.Background(), in)
	if err != nil || len(r.Effects.Session.Metadata) != 2 || len(r.Effects.RefreshToken.Metadata) != 2 {
		t.Fatalf("legal aggregate rejected: %+v %v", r, err)
	}
}
