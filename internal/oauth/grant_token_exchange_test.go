package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/orgrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const (
	cteType    = "https://legacy.acme.test/session"
	cteSubject = "cte-subject-0123456789abcdef"
	cteActor   = "cte-actor-fedcba9876543210"
	cteDB      = "Username-Password-Authentication"
)

type cteFixture struct {
	*actionsFixture
	rec *eventRecorder
}

// newCTEFixture enables custom token exchange for ropg (confidential),
// ropg-public (public), partner (third-party) and leaves other-ropg without
// it. Bind a profile with profile().
func newCTEFixture(t *testing.T) *cteFixture {
	t.Helper()
	f := &cteFixture{actionsFixture: newActionsFixture(t), rec: &eventRecorder{}}
	f.h.Recorder = f.rec
	ctx := context.Background()
	for _, id := range []string{"ropg", "ropg-public", "partner"} {
		c, err := f.st.Clients().Get(ctx, f.tid, id)
		if err != nil {
			t.Fatal(err)
		}
		c.TokenExchangeTypes = []string{"custom_authentication"}
		if err := f.st.Clients().Update(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// profile deploys body as the custom-token-exchange Action of cteType.
func (f *cteFixture) profile(t *testing.T, name, body string) {
	t.Helper()
	a := f.actions.Deploy(t, f.tid, actions.TriggerCustomTokenExchange, name,
		"exports.onExecuteCustomTokenExchange = async (event, api) => {"+body+"};")
	p := &store.TokenExchangeProfile{TenantID: f.tid, ID: "tep_" + name, Name: name, SubjectTokenType: cteType, ActionID: a.ID, Type: "custom_authentication"}
	if err := f.st.ClientCredentials().CreateProfile(context.Background(), p, 100); err != nil {
		t.Fatal(err)
	}
}

func cteForm(clientID, secret string, extra ...string) url.Values {
	v := url.Values{"grant_type": {GrantTokenExchange}, "client_id": {clientID}, "subject_token": {cteSubject}, "subject_token_type": {cteType}}
	if secret != "" {
		v.Set("client_secret", secret)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		v.Set(extra[i], extra[i+1])
	}
	return v
}

func (f *cteFixture) codes() []string {
	var out []string
	for _, e := range f.rec.events {
		out = append(out, e.Type)
	}
	return out
}

func (f *cteFixture) user(t *testing.T, id string) *store.User {
	t.Helper()
	u, err := f.st.Users().Get(context.Background(), f.tid, id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTokenExchangeHappyPath(t *testing.T) {
	f := newCTEFixture(t)
	alice := f.aliceID(t)
	f.profile(t, "happy", fmt.Sprintf(`if (event.transaction.subject_token !== %q) { api.access.rejectInvalidSubjectToken("bad"); return; }
	  api.authentication.setUserById(%q); api.user.setAppMetadata("plan", "gold");`, cteSubject, alice))
	// Post-login sees the exchange protocol and the patched metadata, never the tokens.
	f.actions.PostLogin(t, f.tid, "observe", fmt.Sprintf(`exports.onExecutePostLogin = async (event, api) => {
	  if (JSON.stringify(event).includes(%q)) throw new Error("subject token in event");
	  if (event.transaction.protocol !== "oauth2-token-exchange") throw new Error("protocol " + event.transaction.protocol);
	  if (event.user.app_metadata.plan !== "gold") throw new Error("metadata not applied");
	};`, cteSubject))
	before := f.user(t, alice).LoginsCount
	status, body := f.token(t, cteForm("ropg", "ropg-secret", "audience", acmeAPI, "scope", "openid offline_access read:things"))
	if status != 200 {
		t.Fatalf("exchange %d %v", status, body)
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if at["sub"] != alice || at["azp"] != "ropg" || at["act"] != nil || !strings.Contains(at["scope"].(string), "read:things") {
		t.Fatalf("access token = %v", at)
	}
	idt, _ := verifyToken(t, f.keys, f.tid, body["id_token"].(string))
	if idt["sub"] != alice || idt["aud"] != "ropg" {
		t.Fatalf("id token = %v", idt)
	}
	if rt, _ := body["refresh_token"].(string); rt == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	if got := f.codes(); len(got) != 1 || got[0] != "secte" || f.rec.events[0].UserID != alice {
		t.Fatalf("events = %v %+v", got, f.rec.events)
	}
	u := f.user(t, alice)
	if u.AppMetadata["plan"] != "gold" || u.LoginsCount != before+1 {
		t.Fatalf("user after exchange: metadata=%v logins=%d (before %d)", u.AppMetadata, u.LoginsCount, before)
	}
}

func TestTokenExchangeActorNoRefresh(t *testing.T) {
	f := newCTEFixture(t)
	alice := f.aliceID(t)
	f.profile(t, "actor", fmt.Sprintf(`api.authentication.setUserById(%q);
	  api.authentication.setActor({sub: "agent-1", role: "assistant", act: {sub: "agent-0"}});`, alice))
	status, body := f.token(t, cteForm("ropg", "ropg-secret", "audience", acmeAPI, "scope", "openid offline_access read:things",
		"actor_token", cteActor, "actor_token_type", "urn:ietf:params:oauth:token-type:access_token"))
	if status != 200 {
		t.Fatalf("exchange %d %v", status, body)
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	raw, _ := json.Marshal(at["act"])
	if string(raw) != `{"act":{"sub":"agent-0"},"role":"assistant","sub":"agent-1"}` {
		t.Fatalf("act = %s", raw)
	}
	if _, ok := body["refresh_token"]; ok {
		t.Fatalf("refresh token issued with an actor: %v", body)
	}
	if len(f.rec.events) != 1 || f.rec.events[0].Type != "secte" || f.rec.events[0].Details["actor"] == nil {
		t.Fatalf("events = %+v", f.rec.events)
	}
}

// The act claim is signed into HS256 access tokens too.
func TestTokenExchangeActorHS256(t *testing.T) {
	m := &Minter{Now: fixedNow}
	raw, err := m.AccessToken(context.Background(), AccessTokenParams{SigningAlg: "HS256", SigningSecret: []byte("0123456789abcdef0123"),
		Issuer: "https://a.example.test/", Subject: "auth0|u", Audience: []string{"https://api.test"}, ClientID: "c",
		Actor: map[string]any{"sub": "agent-1"}})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if act, _ := claims["act"].(map[string]any); act["sub"] != "agent-1" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestTokenExchangeClientRules(t *testing.T) {
	f := newCTEFixture(t)
	f.profile(t, "rules", fmt.Sprintf(`api.authentication.setUserById(%q);`, f.aliceID(t)))
	for name, tc := range map[string]struct {
		form   url.Values
		status int
		code   string
	}{
		"third-party":            {cteForm("partner", "partner-secret"), 403, "unauthorized_client"},
		"without token_exchange": {cteForm("other-ropg", "other-secret"), 403, "unauthorized_client"},
		"unknown type":           {cteForm("ropg", "ropg-secret", "subject_token_type", "https://unknown.acme.test/t"), 400, "invalid_request"},
		"no consent skip":        {cteForm("ropg", "ropg-secret", "audience", "https://granted.test"), 403, "access_denied"},
		"no subject token":       {cteForm("ropg", "ropg-secret", "subject_token", ""), 400, "invalid_request"},
		"actor without type":     {cteForm("ropg", "ropg-secret", "actor_token", cteActor), 400, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := f.token(t, tc.form)
			if status != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", status, body, tc.status, tc.code)
			}
		})
	}
}

func TestTokenExchangeUnavailableWithoutCapability(t *testing.T) {
	f := newCTEFixture(t)
	f.h.Store = noClientCredentials{f.st}
	status, body := f.token(t, cteForm("ropg", "ropg-secret"))
	if status != 400 || body["error"] != "unsupported_grant_type" {
		t.Fatalf("got %d %v", status, body)
	}
}

type noClientCredentials struct{ store.Store }

func (noClientCredentials) ClientCredentials() store.ClientCredentials {
	return store.UnimplementedClientCredentials{}
}

func TestTokenExchangeThrottle(t *testing.T) {
	f := newCTEFixture(t)
	ctx := context.Background()
	tn, err := f.st.Tenants().Get(ctx, f.tid)
	if err != nil {
		t.Fatal(err)
	}
	tn.ProtectionSettings.SuspiciousIP.Stage.PreCustomTokenExchange = store.ProtectionRate{MaxAttempts: 2, Rate: 3600000}
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.profile(t, "reject", `api.access.rejectInvalidSubjectToken("expired");`)
	for i := range 2 {
		status, body := f.token(t, cteForm("ropg", "ropg-secret"))
		if status != 400 || body["error"] != "invalid_request" {
			t.Fatalf("attempt %d: %d %v", i, status, body)
		}
	}
	status, body := f.token(t, cteForm("ropg", "ropg-secret"))
	if status != 429 || body["error"] != "too_many_attempts" || body["error_description"] != tokenExchangeBlocked {
		t.Fatalf("third attempt: %d %v", status, body)
	}
	if got := strings.Join(f.codes(), " "); got != "fecte fecte limit_mu fecte" {
		t.Fatalf("events = %s", got)
	}
}

// A request that is not a rejected subject token gives its attempt back.
func TestTokenExchangeThrottleRefundsOtherOutcomes(t *testing.T) {
	f := newCTEFixture(t)
	ctx := context.Background()
	tn, _ := f.st.Tenants().Get(ctx, f.tid)
	tn.ProtectionSettings.SuspiciousIP.Stage.PreCustomTokenExchange = store.ProtectionRate{MaxAttempts: 1, Rate: 3600000}
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.profile(t, "deny", `api.access.deny("not_welcome", "no");`)
	for i := range 3 {
		if status, body := f.token(t, cteForm("ropg", "ropg-secret")); status != 400 || body["error"] != "not_welcome" {
			t.Fatalf("attempt %d: %d %v", i, status, body)
		}
	}
}

func TestTokenExchangeActionFailureModes(t *testing.T) {
	newUser := "auth0|cte-new-1"
	create := `api.authentication.setUserByConnection("` + cteDB + `", {user_id: "cte-new-1", email: "cte-new@acme.test"});`
	for name, tc := range map[string]struct {
		body   string
		status int
		code   string
	}{
		"throw":     {create + `throw new Error("boom " + event.transaction.subject_token);`, 500, "server_error"},
		"timeout":   {create + `await new Promise(() => {});`, 500, "server_error"},
		"no user":   {`api.user.setAppMetadata("k", 1); console.log(event.transaction.subject_token);`, 500, "server_error"},
		"deny":      {create + `api.access.deny("unauthorized_subject", "the subject is not welcome");`, 400, "unauthorized_subject"},
		"rejected":  {create + `api.access.rejectInvalidSubjectToken("expired");`, 400, "invalid_request"},
		"not found": {`api.authentication.setUserById("auth0|nobody");`, 400, "invalid_request"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCTEFixture(t)
			f.actions.Engine.FlowBudget = 2 * time.Second
			ctx := context.Background()
			var output bytes.Buffer
			f.h.Log = slog.New(logscrub.Handler(slog.NewJSONHandler(&output, nil)))
			recorder := logs.NewRecorder(f.st, logs.Config{Now: fixedNow}, f.h.Log)
			f.h.Recorder = recorder
			f.profile(t, "fail", tc.body)
			form := cteForm("ropg", "ropg-secret", "actor_token", cteActor, "actor_token_type", "urn:x:actor")
			r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			// Value masking, not only key masking, must hide the tokens.
			r.Header.Set("User-Agent", "agent "+cteSubject+" "+cteActor)
			w := httptest.NewRecorder()
			tenant.NewResolver(f.st.Tenants(), "", false).Middleware(http.HandlerFunc(f.h.OauthToken)).ServeHTTP(w, r)
			var resp map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if w.Code != tc.status || resp["error"] != tc.code {
				t.Fatalf("got %d %v", w.Code, resp)
			}
			if _, ok := resp["access_token"]; ok {
				t.Fatal("tokens issued")
			}
			if _, err := f.st.Users().Get(ctx, f.tid, newUser); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("user created: %v", err)
			}
			if err := recorder.Flush(ctx); err != nil {
				t.Fatal(err)
			}
			rows, _, err := f.st.Logs().SearchLogs(ctx, f.tid, nil, store.LogPage{PerPage: 100})
			if err != nil {
				t.Fatal(err)
			}
			sawFecte := false
			for _, row := range rows {
				var event map[string]any
				if err := json.Unmarshal(row.Body, &event); err != nil {
					t.Fatal(err)
				}
				if event["type"] == "fecte" {
					sawFecte = true
				}
				if strings.Contains(string(row.Body), cteSubject) || strings.Contains(string(row.Body), cteActor) {
					t.Errorf("token in tenant log: %s", row.Body)
				}
			}
			if !sawFecte {
				t.Errorf("no fecte among %d rows", len(rows))
			}
			for _, sink := range []string{output.String(), f.actions.Logs.String()} {
				if strings.Contains(sink, cteSubject) || strings.Contains(sink, cteActor) {
					t.Errorf("token in server log: %s", sink)
				}
			}
		})
	}
}

func TestTokenExchangeMasksTokensAtIngress(t *testing.T) {
	form := url.Values{"subject_token": {cteSubject}, "actor_token": {cteActor}}
	r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, oerr := parseTokenRequest(httptest.NewRecorder(), r); oerr != nil {
		t.Fatal(oerr)
	}
	for _, v := range []string{cteSubject, cteActor} {
		if got := logscrub.MaskText(r.Context(), "x "+v); got != "x "+logscrub.Marker {
			t.Fatalf("%q not masked: %q", v, got)
		}
	}
	for _, k := range []string{"subject_token", "actor_token"} {
		if !logscrub.SensitiveKey(k) {
			t.Fatalf("%s is not a sensitive key", k)
		}
	}
}

func TestTokenExchangePostLoginMFARefused(t *testing.T) {
	f := newCTEFixture(t)
	ctx := context.Background()
	tn, _ := f.st.Tenants().Get(ctx, f.tid)
	if tn.SettingsExtra == nil {
		tn.SettingsExtra = map[string]any{}
	}
	tn.SettingsExtra["customize_mfa_in_postlogin_action"] = true
	if err := f.st.Tenants().Update(ctx, tn); err != nil {
		t.Fatal(err)
	}
	f.profile(t, "mfa", fmt.Sprintf(`api.authentication.setUserById(%q);`, f.aliceID(t)))
	f.actions.PostLogin(t, f.tid, "challenge", `exports.onExecutePostLogin = async (event, api) => { api.authentication.challengeWith({type: "otp"}); };`)
	status, body := f.token(t, cteForm("ropg", "ropg-secret", "scope", "openid"))
	if status != 403 || body["error"] != "access_denied" || !strings.Contains(fmt.Sprint(body["error_description"]), "multifactor") || body["access_token"] != nil {
		t.Fatalf("got %d %v", status, body)
	}
	if got := f.codes(); len(got) != 1 || got[0] != "fecte" {
		t.Fatalf("events = %v", got)
	}
}

func TestTokenExchangeSetUserByConnectionImmutableEmail(t *testing.T) {
	f := newCTEFixture(t)
	f.profile(t, "byconn", `const email = event.transaction.requested_scopes.includes("profile") ? "changed@acme.test" : "ext9@acme.test";
	  api.authentication.setUserByConnection("`+cteDB+`", {user_id: "ext-9", email, name: "Ext Nine"}, {updateBehavior: "replace"});`)
	// The first exchange creates the user.
	status, body := f.token(t, cteForm("ropg", "ropg-secret", "scope", "openid"))
	if status != 200 {
		t.Fatalf("create %d %v", status, body)
	}
	u := f.user(t, "auth0|ext-9")
	if u.Email != "ext9@acme.test" || u.Name != "Ext Nine" || len(u.Identities) != 1 || u.Identities[0].Connection != cteDB {
		t.Fatalf("created user = %+v", u)
	}
	// The same email again finds the same user.
	if status, body = f.token(t, cteForm("ropg", "ropg-secret", "scope", "openid")); status != 200 {
		t.Fatalf("repeat %d %v", status, body)
	}
	// A different email for an existing user is refused.
	status, body = f.token(t, cteForm("ropg", "ropg-secret", "scope", "openid profile"))
	if status != 400 || body["error"] != "invalid_request" {
		t.Fatalf("changed email %d %v", status, body)
	}
	if u := f.user(t, "auth0|ext-9"); u.Email != "ext9@acme.test" {
		t.Fatalf("email changed to %q", u.Email)
	}
}

func TestTokenExchangeSetUserByConnectionRules(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		edit func(*testing.T, *cteFixture)
	}{
		"creation none":      {body: `api.authentication.setUserByConnection("` + cteDB + `", {user_id: "missing", email: "m@acme.test"}, {creationBehavior: "none"});`},
		"unknown connection": {body: `api.authentication.setUserByConnection("Nope", {user_id: "x", email: "x@acme.test"});`},
		// Other-DB is enabled for ropg only; the public client sends this one.
		"not enabled": {body: `api.authentication.setUserByConnection("Other-DB", {user_id: "x", email: "x@acme.test"});`},
		"import mode": {body: `api.authentication.setUserByConnection("` + cteDB + `", {user_id: "x", email: "x@acme.test"});`, edit: func(t *testing.T, f *cteFixture) {
			ctx := context.Background()
			conn, err := f.st.Connections().GetByName(ctx, f.tid, cteDB)
			if err != nil {
				t.Fatal(err)
			}
			conn.EnabledDatabaseCustomization, conn.ImportMode = true, true
			conn.CustomScripts = map[string]string{"login": "x", "get_user": "x"}
			if err := f.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
		}},
		"blocked user": {body: `api.authentication.setUserById(event.transaction.subject_token);`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCTEFixture(t)
			if tc.edit != nil {
				tc.edit(t, f)
			}
			f.profile(t, "rules", tc.body)
			form := cteForm("ropg", "ropg-secret")
			switch name {
			case "not enabled":
				form = cteForm("ropg-public", "")
			case "blocked user":
				carol, err := f.st.Users().FindByLogin(context.Background(), f.tid, cteDB, "carol@acme.test")
				if err != nil {
					t.Fatal(err)
				}
				form.Set("subject_token", carol.UserID)
			}
			status, body := f.token(t, form)
			want := "invalid_request"
			if name == "blocked user" {
				want = "invalid_grant"
			}
			if status != 400 || body["error"] != want {
				t.Fatalf("got %d %v", status, body)
			}
			if _, err := f.st.Users().Get(context.Background(), f.tid, "auth0|x"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("user created: %v", err)
			}
		})
	}
}

func TestTokenExchangeOrganization(t *testing.T) {
	f := newCTEFixture(t)
	ctx := context.Background()
	alice := f.aliceID(t)
	conn, err := f.st.Connections().GetByName(ctx, f.tid, cteDB)
	if err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: f.tid, ID: orgrules.NewID(), Name: "acme-corp", DisplayName: "Acme", ThirdPartyClientAccess: "allow"}
	other := &store.Organization{TenantID: f.tid, ID: orgrules.NewID(), Name: "other-corp", DisplayName: "Other", ThirdPartyClientAccess: "allow"}
	for _, o := range []*store.Organization{org, other} {
		if err := f.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: f.tid, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatalf("create %s: %v", o.Name, err)
		}
	}
	if err := f.st.Organizations().AddMembers(ctx, f.tid, org.ID, []string{alice}); err != nil {
		t.Fatal(err)
	}
	f.setOrgUsage(t, "ropg", "allow", "")
	f.profile(t, "org", fmt.Sprintf(`api.authentication.setUserById(%q);
	  if (event.transaction.subject_token !== %q) api.authentication.setOrganization(event.transaction.subject_token);`, alice, cteSubject))

	t.Run("request organization", func(t *testing.T) {
		status, body := f.token(t, cteForm("ropg", "ropg-secret", "organization", org.ID, "scope", "openid"))
		if status != 200 {
			t.Fatalf("%d %v", status, body)
		}
		at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
		if at["org_id"] != org.ID {
			t.Fatalf("access token = %v", at)
		}
	})
	t.Run("Action organization by name", func(t *testing.T) {
		status, body := f.token(t, cteForm("ropg", "ropg-secret", "subject_token", "acme-corp"))
		if status != 200 {
			t.Fatalf("%d %v", status, body)
		}
		at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
		if at["org_id"] != org.ID {
			t.Fatalf("access token = %v", at)
		}
	})
	t.Run("both differ", func(t *testing.T) {
		status, body := f.token(t, cteForm("ropg", "ropg-secret", "organization", org.ID, "subject_token", other.ID))
		if status != 400 || body["error"] != "invalid_request" {
			t.Fatalf("%d %v", status, body)
		}
	})
	t.Run("not a member", func(t *testing.T) {
		status, body := f.token(t, cteForm("ropg", "ropg-secret", "organization", other.ID))
		if status != 400 || body["error"] != "invalid_grant" || body["access_token"] != nil {
			t.Fatalf("%d %v", status, body)
		}
	})
}

func TestTokenExchangePublicClient(t *testing.T) {
	f := newCTEFixture(t)
	alice := f.aliceID(t)
	f.profile(t, "public", fmt.Sprintf(`api.authentication.setUserById(%q);`, alice))
	status, body := f.token(t, cteForm("ropg-public", "", "audience", acmeAPI, "scope", "openid"))
	if status != 200 {
		t.Fatalf("%d %v", status, body)
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if at["sub"] != alice || at["azp"] != "ropg-public" {
		t.Fatalf("access token = %v", at)
	}
}

// An actor token that is this tenant's ID token reaches the Action as
// actor_token_user; anything else does not.
func TestTokenExchangeActorTokenUser(t *testing.T) {
	f := newCTEFixture(t)
	alice := f.aliceID(t)
	// The Action selects alice only when actor_token_user names her.
	f.profile(t, "actoruser", `const u = event.transaction.actor_token_user;
	  if (!u) { api.access.deny("no_actor_user", "none"); return; }
	  api.authentication.setUserById(u.user_id);`)
	status, body := f.token(t, pw("ropg", "ropg-secret", "alice@acme.test", "alice password 1", "scope", "openid"))
	if status != 200 {
		t.Fatalf("password grant %d %v", status, body)
	}
	idToken := body["id_token"].(string)
	status, body = f.token(t, cteForm("ropg", "ropg-secret", "actor_token", idToken, "actor_token_type", "urn:ietf:params:oauth:token-type:id_token"))
	if status != 200 {
		t.Fatalf("exchange %d %v", status, body)
	}
	at, _ := verifyToken(t, f.keys, f.tid, body["access_token"].(string))
	if at["sub"] != alice {
		t.Fatalf("access token = %v", at)
	}
	// An access token of the tenant is not an ID token.
	accessToken := body["access_token"].(string)
	for _, tok := range []string{accessToken, idToken[:len(idToken)-4] + "AAAA"} {
		status, body = f.token(t, cteForm("ropg", "ropg-secret", "actor_token", tok, "actor_token_type", "urn:ietf:params:oauth:token-type:id_token"))
		if status != 400 || body["error"] != "no_actor_user" {
			t.Fatalf("untrusted actor token: %d %v", status, body)
		}
	}
}

// An organization the Action names is resolved, and checked against the
// request's, before any user is created.
func TestTokenExchangeOrganizationBeforeUserCreation(t *testing.T) {
	f := newCTEFixture(t)
	ctx := context.Background()
	conn, err := f.st.Connections().GetByName(ctx, f.tid, cteDB)
	if err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: f.tid, ID: orgrules.NewID(), Name: "acme-corp", DisplayName: "Acme", ThirdPartyClientAccess: "allow"}
	other := &store.Organization{TenantID: f.tid, ID: orgrules.NewID(), Name: "other-corp", DisplayName: "Other", ThirdPartyClientAccess: "allow"}
	for _, o := range []*store.Organization{org, other} {
		if err := f.st.Organizations().Create(ctx, o, []store.OrganizationConnection{{TenantID: f.tid, OrganizationID: o.ID, ConnectionID: conn.ID, ShowAsButton: true}}); err != nil {
			t.Fatal(err)
		}
	}
	f.setOrgUsage(t, "ropg", "allow", "")
	f.actions.Bind(t, f.tid, actions.TriggerPreUserRegistration, f.actions.Deploy(t, f.tid, actions.TriggerPreUserRegistration, "prereg",
		`exports.onExecutePreUserRegistration = async (event, api) => { api.user.setAppMetadata("registered", true); };`))
	f.profile(t, "orgcreate", `api.authentication.setUserByConnection("`+cteDB+`", {user_id: "org-new-1", email: "org-new@acme.test"});
	  api.authentication.setOrganization(event.transaction.subject_token);`)
	for name, form := range map[string]url.Values{
		"unknown organization": cteForm("ropg", "ropg-secret", "subject_token", "no-such-org"),
		"organizations differ": cteForm("ropg", "ropg-secret", "subject_token", other.ID, "organization", org.ID),
	} {
		t.Run(name, func(t *testing.T) {
			f.rec.events = nil
			status, body := f.token(t, form)
			if status != 400 || body["error"] != "invalid_request" {
				t.Fatalf("got %d %v", status, body)
			}
			if _, err := f.st.Users().Get(ctx, f.tid, "auth0|org-new-1"); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("user created before the organization check: %v", err)
			}
			if got := f.codes(); len(got) != 1 || got[0] != "fecte" {
				t.Fatalf("events = %v", got)
			}
		})
	}
}
