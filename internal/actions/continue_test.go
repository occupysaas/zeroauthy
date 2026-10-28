package actions_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func resume(t *testing.T, h *harness, tenantID, state string, sess *store.LoginSession, req actions.RequestInfo) (*actions.Result, error) {
	t.Helper()
	return h.eng.ContinuePostLogin(context.Background(), tenantID, state, sess, req)
}
func redirectInput(h *harness) actions.PostLoginInput {
	in := h.loginInput("t1")
	in.CanRedirect = true
	in.Session = &store.LoginSession{TenantID: "t1", ID: "session1", UserID: in.User.UserID}
	return in
}
func redirectState(t *testing.T, r *actions.Result, err error) string {
	t.Helper()
	if err != nil || r == nil || r.Redirect == nil {
		t.Fatalf("redirect = %+v, %v", r, err)
	}
	u, e := url.Parse(r.Redirect.URL)
	if e != nil {
		t.Fatal(e)
	}
	s := u.Query().Get("state")
	if s == "" {
		t.Fatal("missing redirect state")
	}
	return s
}
func TestActionsRedirectRoundTrip(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if err := h.st.RBAC().CreateRole(ctx, &store.Role{TenantID: "t1", ID: "rol_admin", Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := h.st.RBAC().ChangeUserRoles(ctx, "t1", "auth0|u1", true, []string{"rol_admin"}); err != nil {
		t.Fatal(err)
	}
	first := h.action("t1", trigLogin, "first", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.idToken.setCustomClaim('before',1);a.transaction.setMetadata('phase','one');a.redirect.sendUserTo('https://step.test/check?keep=yes',{query:{a:'1',state:'spoof'}})}; exports.onContinuePostLogin=async(e,a)=>{if(e.authorization.roles[0]!=="admin"||(await a.roles.getUserEffectiveRoles()).roles[0].name!=="admin")throw Error("roles changed");if(e.request.query.answer!=='yes'||e.request.body.extra!=='posted'||e.transaction.metadata.phase!=='one'||!e.user.app_metadata.held)throw Error('lost event');a.idToken.setCustomClaim('after',2)};`, nil, false)
	second := h.action("t1", trigLogin, "second", `exports.onExecutePostLogin=(e,a)=>{a.idToken.setCustomClaim('remaining','pinned')}`, nil, false)
	h.bind("t1", trigLogin, first, second)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(ctx, in)
	state := redirectState(t, r, err)
	u, _ := url.Parse(r.Redirect.URL)
	if u.Query().Get("a") != "1" || u.Query().Get("keep") != "yes" || state == "spoof" {
		t.Fatal(u)
	}
	if h.user("t1").AppMetadata["held"] != nil {
		t.Fatal("metadata committed before continuation")
	}
	// Editing roles, bindings or deployments cannot change a suspended flow.
	if err := h.st.RBAC().ChangeUserRoles(ctx, "t1", "auth0|u1", false, []string{"rol_admin"}); err != nil {
		t.Fatal(err)
	}
	cur := h.user("t1")
	cur.AppMetadata["concurrent"] = "retained"
	if err := h.st.Users().Update(ctx, cur); err != nil {
		t.Fatal(err)
	}
	h.redeploy(second, `exports.onExecutePostLogin=()=>{throw Error('new version')}`)
	h.bind("t1", trigLogin, second)
	r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test", Method: "POST", Query: map[string]any{"answer": "yes"}, Body: map[string]any{"extra": "posted"}})
	if err != nil || r.Redirect != nil || r.Effects.IDClaims["before"] != float64(1) || r.Effects.IDClaims["after"] != float64(2) || r.Effects.IDClaims["remaining"] != "pinned" {
		t.Fatalf("resume: %+v %v", r, err)
	}
	if h.user("t1").AppMetadata["held"] != true || h.user("t1").AppMetadata["concurrent"] != "retained" {
		t.Fatal("held metadata not committed at flow end")
	}
	if _, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"}); !errors.Is(err, actions.ErrInvalidContinue) {
		t.Fatal("replayed state accepted")
	}
}
func TestActionsContinueRejects(t *testing.T) {
	for _, tc := range []string{"missing", "wrong", "expired", "other-session", "other-tenant", "other-origin", "other-user", "copied-to-tenant", "copied-to-session", "copied-to-state", "tampered"} {
		t.Run(tc, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			a := h.action("t1", trigLogin, "redirect", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=()=>{};`, nil, false)
			h.bind("t1", trigLogin, a)
			in := redirectInput(h)
			r, err := h.eng.PostLogin(ctx, in)
			state := redirectState(t, r, err)
			tid := "t1"
			sess := *in.Session
			req := actions.RequestInfo{Hostname: "t1.example.test"}
			switch tc {
			case "missing":
				state = ""
			case "wrong":
				state = "invalid"
			case "expired":
				h.advance(15 * time.Minute)
			case "other-session":
				sess.ID = "other"
			case "other-tenant":
				tid = "t2"
			case "other-origin":
				req.Hostname = "alias.example.test"
			case "other-user":
				sess.UserID = "auth0|other"
			case "copied-to-tenant", "copied-to-session", "copied-to-state":
				c, e := h.st.Actions().ConsumeContinue(ctx, tid, secrets.HashToken(state), h.clock())
				if e != nil {
					t.Fatal(e)
				}
				switch tc {
				case "copied-to-tenant":
					tid = "t2"
					sess.TenantID = tid
					c.TenantID = tid
					req.Hostname = "t2.example.test"
				case "copied-to-session":
					sess.ID = "new-session"
					c.SessionID = sess.ID
				case "copied-to-state":
					state = "another-state"
					c.StateHash = secrets.HashToken(state)
				}
				if e = h.st.Actions().CreateContinue(ctx, c); e != nil {
					t.Fatal(e)
				}
			case "tampered":
				c, e := h.st.Actions().ConsumeContinue(ctx, tid, secrets.HashToken(state), h.clock())
				if e != nil {
					t.Fatal(e)
				}
				c.Sealed[len(c.Sealed)-1] ^= 1
				if e = h.st.Actions().CreateContinue(ctx, c); e != nil {
					t.Fatal(e)
				}
			}
			if _, err = resume(t, h, tid, state, &sess, req); !errors.Is(err, actions.ErrInvalidContinue) {
				t.Fatal("invalid continuation accepted")
			}
			if h.user("t1").AppMetadata["held"] != nil {
				t.Fatal("rejected state committed held metadata")
			}
		})
	}
	t.Run("sixth redirect fails closed", func(t *testing.T) {
		h := newHarness(t)
		a := h.action("t1", trigLogin, "loop", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.test/');`, nil, false)
		h.bind("t1", trigLogin, a)
		in := redirectInput(h)
		r, err := h.eng.PostLogin(context.Background(), in)
		for n := 1; n <= 5; n++ {
			state := redirectState(t, r, err)
			r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
		}
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) || r != nil {
			t.Fatalf("sixth redirect: %+v %v", r, err)
		}
		if h.user("t1").AppMetadata["held"] != nil {
			t.Fatal("failed chain committed metadata")
		}
	})
}
func TestActionsRedirectTokens(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "tokens", `exports.onExecutePostLogin=(e,a)=>{let token=a.redirect.encodeToken({secret:'shared',payload:{custom:'value'}});let short=a.redirect.encodeToken({secret:'shared',expiresInSeconds:42,payload:{custom:'short'}});a.redirect.sendUserTo('https://step.test/',{query:{token,short}})};exports.onContinuePostLogin=(e,a)=>{let p=a.redirect.validateToken({secret:'shared',tokenParameterName:'proof'});a.idToken.setCustomClaim('verified',p.custom)};`, nil, false)
	h.bind("t1", trigLogin, a)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(context.Background(), in)
	state := redirectState(t, r, err)
	u, _ := url.Parse(r.Redirect.URL)
	tok := u.Query().Get("token")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal(tok)
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var p map[string]any
	if err = json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if p["sub"] != "auth0|u1" || p["iss"] != "t1.example.test" || p["ip"] != "203.0.113.9" || p["exp"].(float64)-p["iat"].(float64) != 900 || p["custom"] != "value" {
		t.Fatal(p)
	}
	m := hmac.New(sha256.New, []byte("shared"))
	m.Write([]byte(parts[0] + "." + parts[1]))
	if base64.RawURLEncoding.EncodeToString(m.Sum(nil)) != parts[2] {
		t.Fatal("encodeToken did not sign with HS256")
	}
	short := strings.Split(u.Query().Get("short"), ".")
	if len(short) != 3 {
		t.Fatal(short)
	}
	b, _ = base64.RawURLEncoding.DecodeString(short[1])
	if err = json.Unmarshal(b, &p); err != nil || p["exp"].(float64)-p["iat"].(float64) != 42 {
		t.Fatalf("explicit TTL: %v %v", p, err)
	}
	// A token created before the redirect has no continuation state and must be refused.
	if _, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test", Query: map[string]any{"proof": tok}}); err == nil {
		t.Fatal("token without state accepted")
	}
}

// signRedirectToken models the external page that signs a token containing the
// received continuation state; it does not use the runner's token helpers.
func signRedirectToken(t *testing.T, secret, alg string, claims map[string]any) string {
	t.Helper()
	part := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	data := part(map[string]any{"alg": alg, "typ": "JWT"}) + "." + part(claims)
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(data))
	return data + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func TestActionsRedirectTokenValidation(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "verify", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('pending',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>{const opts={secret:'shared'};if(e.request.body.named)opts.tokenParameterName='proof';let p=a.redirect.validateToken(opts);a.idToken.setCustomClaim('verified',p.custom)};`, nil, false)
	h.bind("t1", trigLogin, a)
	for _, tc := range []string{"query", "body", "named", "bad-signature", "expired", "missing-state", "wrong-state", "wrong-algorithm", "missing-token", "malformed"} {
		t.Run(tc, func(t *testing.T) {
			in := redirectInput(h)
			r, err := h.eng.PostLogin(context.Background(), in)
			state := redirectState(t, r, err)
			p := map[string]any{"state": state, "exp": time.Now().Add(time.Minute).Unix(), "custom": "verified"}
			secret, alg := "shared", "HS256"
			switch tc {
			case "bad-signature":
				secret = "other"
			case "expired":
				p["exp"] = time.Now().Add(-time.Second).Unix()
			case "missing-state":
				delete(p, "state")
			case "wrong-state":
				p["state"] = "other"
			case "wrong-algorithm":
				alg = "HS512"
			}
			tok := signRedirectToken(t, secret, alg, p)
			req := actions.RequestInfo{Hostname: "t1.example.test", Query: map[string]any{}, Body: map[string]any{}}
			switch tc {
			case "body":
				req.Body["session_token"] = tok
			case "named":
				req.Body["named"] = true
				req.Body["proof"] = tok
			case "missing-token":
			case "malformed":
				req.Query["session_token"] = "broken"
			default:
				req.Query["session_token"] = tok
			}
			r, err = resume(t, h, "t1", state, in.Session, req)
			valid := tc == "query" || tc == "body" || tc == "named"
			if valid {
				if err != nil || r.Effects.IDClaims["verified"] != "verified" {
					t.Fatalf("valid token: %+v %v", r, err)
				}
			} else if err == nil || r != nil {
				t.Fatalf("invalid token: %+v %v", r, err)
			}
		})
	}
}
func TestActionsContinueSingleUseRace(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "race", `exports.onExecutePostLogin=(e,a)=>a.redirect.sendUserTo('https://step.test/');exports.onContinuePostLogin=(e,a)=>a.idToken.setCustomClaim('once',true);`, nil, false)
	h.bind("t1", trigLogin, a)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(context.Background(), in)
	state := redirectState(t, r, err)
	var wg sync.WaitGroup
	success := make(chan bool, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := h.eng.ContinuePostLogin(context.Background(), "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
			success <- err == nil && r.Effects.IDClaims["once"] == true
		}()
	}
	wg.Wait()
	close(success)
	n := 0
	for ok := range success {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("successful resumes=%d", n)
	}
}
func TestActionsContinuePurge(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "purge", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};`, nil, false)
	h.bind("t1", trigLogin, a)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(context.Background(), in)
	state := redirectState(t, r, err)
	if n, err := actions.PurgeContinue(context.Background(), h.st, h.clock()); n != 0 || err != nil {
		t.Fatalf("early purge=%d %v", n, err)
	}
	h.advance(15*time.Minute + time.Second)
	if n, err := actions.PurgeContinue(context.Background(), h.st, h.clock()); n != 1 || err != nil {
		t.Fatalf("expired purge=%d %v", n, err)
	}
	if _, err := resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"}); !errors.Is(err, actions.ErrInvalidContinue) {
		t.Fatal(err)
	}
	if h.user("t1").AppMetadata["held"] != nil {
		t.Fatal("purge committed metadata")
	}
}

func TestActionsContinueSuspensionAtomic(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "atomic", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};`, nil, false)
	h.bind("t1", trigLogin, a)
	h.eng.Store = failingStore{Store: h.st, failExec: true}
	r, err := h.eng.PostLogin(context.Background(), redirectInput(h))
	if err == nil || r != nil {
		t.Fatalf("record failure returned success: %+v %v", r, err)
	}
	if n, err := actions.PurgeContinue(context.Background(), h.st, h.clock().Add(time.Hour)); n != 0 || err != nil {
		t.Fatalf("failed suspension left %d continuation records: %v", n, err)
	}
	if h.user("t1").AppMetadata["held"] != nil {
		t.Fatal("failed suspension committed metadata")
	}
}

func TestActionsContinueFlowBudget(t *testing.T) {
	h := newHarness(t)
	h.eng.FlowBudget = time.Second
	a := h.action("t1", trigLogin, "budget", `exports.onExecutePostLogin=async(e,a)=>{await new Promise(r=>setTimeout(r,100));a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=async()=>{await new Promise(r=>setTimeout(r,950))};`, nil, false)
	h.bind("t1", trigLogin, a)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(context.Background(), in)
	state := redirectState(t, r, err)
	r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
	if r != nil || !errors.Is(err, actions.ErrTimeout) {
		t.Fatalf("resuming reset the flow budget: %+v %v", r, err)
	}
}
func TestActionsRedirectMultipleActions(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigLogin, "one", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('phase','one');a.redirect.sendUserTo('https://one.test/')};exports.onContinuePostLogin=(e,a)=>a.idToken.setCustomClaim('one',true);`, nil, false)
	b := h.action("t1", trigLogin, "two", `exports.onExecutePostLogin=(e,a)=>{if(e.user.app_metadata.phase!=='one')throw Error('metadata lost');a.redirect.sendUserTo('https://two.test/')};exports.onContinuePostLogin=(e,a)=>a.idToken.setCustomClaim('two',true);`, nil, false)
	c := h.action("t1", trigLogin, "three", `exports.onExecutePostLogin=(e,a)=>a.idToken.setCustomClaim('three',true);`, nil, false)
	h.bind("t1", trigLogin, a, b, c)
	in := redirectInput(h)
	r, err := h.eng.PostLogin(context.Background(), in)
	state := redirectState(t, r, err)
	r, err = resume(t, h, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
	next := redirectState(t, r, err)
	if next == state || !strings.HasPrefix(r.Redirect.URL, "https://two.test/") {
		t.Fatal(r.Redirect)
	}
	if h.user("t1").AppMetadata["phase"] != nil {
		t.Fatal("metadata committed at intermediate redirect")
	}
	r, err = resume(t, h, "t1", next, in.Session, actions.RequestInfo{Hostname: "t1.example.test"})
	if err != nil || r.Redirect != nil || r.Effects.IDClaims["one"] != true || r.Effects.IDClaims["two"] != true || r.Effects.IDClaims["three"] != true {
		t.Fatalf("pinned tail across redirects: %+v %v", r, err)
	}
}

func TestActionsContinueValidator(t *testing.T) {
	for _, tc := range []string{"allow", "reject", "invalid-envelope"} {
		t.Run(tc, func(t *testing.T) {
			h := newHarness(t)
			ctx := context.Background()
			a := h.action("t1", trigLogin, "validation", `exports.onExecutePostLogin=(e,a)=>{a.user.setAppMetadata('held',true);a.redirect.sendUserTo('https://step.test/')};exports.onContinuePostLogin=(e,a)=>a.idToken.setCustomClaim('resumed',true);`, nil, false)
			h.bind("t1", trigLogin, a)
			in := redirectInput(h)
			in.Continuation = map[string]string{"original": "trusted"}
			r, err := h.eng.PostLogin(ctx, in)
			state := redirectState(t, r, err)
			req := actions.RequestInfo{Hostname: "t1.example.test"}
			if tc == "invalid-envelope" {
				req.Hostname = "other.test"
			}
			rejected := errors.New("policy rejected")
			called := false
			r, err = h.eng.ContinuePostLoginValidated(ctx, "t1", state, in.Session, req, func(ctx context.Context, params map[string]string) error {
				called = true
				if params["original"] != "trusted" {
					t.Fatalf("validator input=%v", params)
				}
				if h.user("t1").AppMetadata["held"] != nil {
					t.Fatal("metadata committed before validation")
				}
				params["original"] = "modified"
				if tc == "reject" {
					return rejected
				}
				return nil
			})
			switch tc {
			case "allow":
				if !called || err != nil || r.Effects.IDClaims["resumed"] != true || r.Continuation["original"] != "trusted" || h.user("t1").AppMetadata["held"] != true {
					t.Fatalf("validated continuation=%+v err=%v called=%v", r, err, called)
				}
			case "reject":
				if !called || !errors.Is(err, rejected) || r != nil || h.user("t1").AppMetadata["held"] != nil {
					t.Fatalf("rejected continuation=%+v err=%v called=%v", r, err, called)
				}
			case "invalid-envelope":
				if called || !errors.Is(err, actions.ErrInvalidContinue) || r != nil {
					t.Fatalf("untrusted input reached validator: %+v %v called=%v", r, err, called)
				}
			}
			if tc != "allow" {
				if n, err := h.st.Actions().PurgeExecutions(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
					t.Fatalf("rejection ran an Action: executions=%d %v", n, err)
				}
			}
			if _, err := h.eng.ContinuePostLogin(ctx, "t1", state, in.Session, actions.RequestInfo{Hostname: "t1.example.test"}); !errors.Is(err, actions.ErrInvalidContinue) {
				t.Fatalf("rejected state remained usable: %v", err)
			}
		})
	}
}
