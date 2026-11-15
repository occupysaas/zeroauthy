package actions_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

const (
	cteSubject = "subject-token-0123456789abcdef"
	cteActor   = "actor-token-fedcba9876543210"
)

func (h *harness) cteInput(tenantID, actionID string) actions.TokenExchangeInput {
	return actions.TokenExchangeInput{
		Tenant:             tenant.Resolved{Tenant: &store.Tenant{ID: tenantID, Name: tenantID}, Host: tenantID + ".example.test"},
		Client:             &store.Client{TenantID: tenantID, ClientID: "cli1", Name: "App"},
		Resource:           &store.ResourceServer{Identifier: "https://api.example.test/"},
		SubjectToken:       cteSubject,
		SubjectTokenType:   "https://example.test/legacy-token",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		RequestedScopes:    []string{"read:a"},
		Request:            actions.RequestInfo{IP: "198.51.100.1", Method: "POST", UserAgent: "ua", Language: "en", Body: map[string]any{"subject_token": cteSubject}},
		ActionID:           actionID,
	}
}

// cte deploys body as a custom-token-exchange Action and runs it.
func (h *harness) cte(tenantID, name, body string, edit func(*actions.TokenExchangeInput)) (*actions.TokenExchangeResult, error) {
	h.t.Helper()
	a := h.action(tenantID, actions.TriggerCustomTokenExchange, name, "exports.onExecuteCustomTokenExchange = async (event, api) => {"+body+"};", nil, false)
	in := h.cteInput(tenantID, a.ID)
	if edit != nil {
		edit(&in)
	}
	return h.eng.CustomTokenExchange(context.Background(), in)
}

func TestCTESetUserByID(t *testing.T) {
	h := newHarness(t)
	r, err := h.cte("t1", "byid", `api.authentication.setUserById("auth0|u1");
	  api.authentication.setOrganization("org_1");
	  api.authentication.setActor({sub: "svc", n: 1, ok: true, act: {sub: "earlier"}});
	  api.user.setAppMetadata("plan", "pro");
	  api.user.setUserMetadata("gone", null);`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.UserID != "auth0|u1" || r.Connection != "" || r.OrganizationRef != "org_1" || r.Denied != nil || r.RejectedSubjectToken {
		t.Fatalf("result = %+v", r)
	}
	if got := mustJSON(t, r.Actor); got != `{"act":{"sub":"earlier"},"n":1,"ok":true,"sub":"svc"}` {
		t.Fatalf("actor = %s", got)
	}
	if r.AppMetadata["plan"] != "pro" {
		t.Fatalf("app_metadata = %v", r.AppMetadata)
	}
	if v, ok := r.UserMetadata["gone"]; !ok || v != nil {
		t.Fatalf("user_metadata = %v", r.UserMetadata)
	}
	// This task resolves no user: the stored user is untouched.
	if u := h.user("t1"); u.AppMetadata["plan"] != "free" {
		t.Fatalf("user changed: %+v", u.AppMetadata)
	}
}

func TestCTESetUserByConnectionDefaults(t *testing.T) {
	h := newHarness(t)
	r, err := h.cte("t1", "byconn", `api.authentication.setUserByConnection("legacy", {user_id: "ext-1", email: "a@example.test", email_verified: true, verify_email: false, phone_number: "+15550100"});`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.UserID != "" || r.Connection != "legacy" || r.CreationBehavior != "create_if_not_exists" || r.UpdateBehavior != "none" ||
		r.Attributes["user_id"] != "ext-1" || r.Attributes["email"] != "a@example.test" || r.Attributes["email_verified"] != true {
		t.Fatalf("result = %+v", r)
	}
	r, err = h.cte("t1", "byconn2", `api.authentication.setUserByConnection("legacy", {user_id: "ext-1"}, {creationBehavior: "none", updateBehavior: "replace"});`, nil)
	if err != nil || r.CreationBehavior != "none" || r.UpdateBehavior != "replace" {
		t.Fatalf("explicit behaviours: %+v %v", r, err)
	}
	for name, body := range map[string]string{
		"noid":       `api.authentication.setUserByConnection("legacy", {email: "a@example.test"});`,
		"badattr":    `api.authentication.setUserByConnection("legacy", {user_id: "x", app_metadata: {}});`,
		"phone":      `api.authentication.setUserByConnection("legacy", {user_id: "x", phone: "+1"});`,
		"verifytype": `api.authentication.setUserByConnection("legacy", {user_id: "x", verify_email: "yes"});`,
		"badtype":    `api.authentication.setUserByConnection("legacy", {user_id: "x", email_verified: "yes"});`,
		"noname":     `api.authentication.setUserByConnection("", {user_id: "x"});`,
		"badcreate":  `api.authentication.setUserByConnection("legacy", {user_id: "x"}, {creationBehavior: "always"});`,
		"badupdate":  `api.authentication.setUserByConnection("legacy", {user_id: "x"}, {updateBehavior: "merge"});`,
		"badoption":  `api.authentication.setUserByConnection("legacy", {user_id: "x"}, {other: 1});`,
		"emptyid":    `api.authentication.setUserById("");`,
		"nonstrid":   `api.authentication.setUserById(7);`,
		"emptyorg":   `api.authentication.setUserById("u"); api.authentication.setOrganization("");`,
		"noactorsub": `api.authentication.setUserById("u"); api.authentication.setActor({n: 1});`,
	} {
		_, err := h.cte("t1", "bad"+name, body, nil)
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) || !errors.Is(err, actions.ErrInvalidCommand) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestCTEBothOrNeither(t *testing.T) {
	h := newHarness(t)
	for name, body := range map[string]string{
		"neither": `api.user.setAppMetadata("k", 1);`,
		"both":    `api.authentication.setUserById("u"); api.authentication.setUserByConnection("c", {user_id: "x"});`,
		"twice":   `api.authentication.setUserById("u"); api.authentication.setUserById("v");`,
	} {
		_, err := h.cte("t1", name, body, nil)
		var fe *actions.ErrFlow
		if !errors.As(err, &fe) || !errors.Is(err, actions.ErrNoUserSelected) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if e := h.execution("t1", fe.ExecutionID); e.Trigger != actions.TriggerCustomTokenExchange || e.Results[0].ErrorID != "no_user_selected" {
			t.Fatalf("%s: execution = %+v", name, e)
		}
	}
}

func TestCTEDeny(t *testing.T) {
	h := newHarness(t)
	r, err := h.cte("t1", "deny", `api.access.deny("unauthorized_subject", "the subject is not welcome"); api.authentication.setUserById("u");`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Denied == nil || r.Denied.Code != "unauthorized_subject" || r.Denied.Reason != "the subject is not welcome" || r.RejectedSubjectToken {
		t.Fatalf("result = %+v denied=%+v", r, r.Denied)
	}
	// A deny needs no user selection.
	r, err = h.cte("t1", "deny2", `api.access.deny("nope", "no");`, nil)
	if err != nil || r.Denied == nil {
		t.Fatalf("deny without user: %+v %v", r, err)
	}
	_, err = h.cte("t1", "denybad", `api.access.deny("bad code\"", "x");`, nil)
	if !errors.Is(err, actions.ErrInvalidCommand) {
		t.Fatalf("bad code: %v", err)
	}
}

func TestCTERejectInvalidSubjectToken(t *testing.T) {
	h := newHarness(t)
	r, err := h.cte("t1", "reject", `api.access.rejectInvalidSubjectToken("expired");`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !r.RejectedSubjectToken || r.Denied != nil {
		t.Fatalf("result = %+v", r)
	}
}

func TestCTEActorLimits(t *testing.T) {
	h := newHarness(t)
	chain := func(depth int) string {
		s := `{sub: "d"}`
		for i := 1; i < depth; i++ {
			s = `{sub: "d", act: ` + s + `}`
		}
		return s
	}
	if r, err := h.cte("t1", "depth5", `api.authentication.setUserById("u"); api.authentication.setActor(`+chain(5)+`);`, nil); err != nil || r.Actor == nil {
		t.Fatalf("depth 5: %+v %v", r, err)
	}
	if r, err := h.cte("t1", "props5", `api.authentication.setUserById("u"); api.authentication.setActor({sub: "a", b: 1, c: 2, d: 3, e: 4, f: 5, act: {sub: "z"}});`, nil); err != nil || len(r.Actor) != 7 {
		t.Fatalf("5 custom properties plus sub and act: %+v %v", r, err)
	}
	for name, body := range map[string]string{
		"depth6":      `api.authentication.setActor(` + chain(6) + `);`,
		"props6":      `api.authentication.setActor({sub: "a", b: 1, c: 2, d: 3, e: 4, f: 5, g: 6});`,
		"nested6":     `api.authentication.setActor({sub: "a", act: {sub: "b", b: 1, c: 2, d: 3, e: 4, f: 5, g: 6}});`,
		"nestednosub": `api.authentication.setActor({sub: "a", act: {b: 1}});`,
		"actnotobj":   `api.authentication.setActor({sub: "a", act: "x"});`,
		"longkey":     `api.authentication.setActor({sub: "a", ["k".repeat(1025)]: 1});`,
		"longval":     `api.authentication.setActor({sub: "a", b: "v".repeat(1025)});`,
		"array":       `api.authentication.setActor({sub: "a", b: [1]});`,
		"nullval":     `api.authentication.setActor({sub: "a", b: null});`,
		"objnotact":   `api.authentication.setActor({sub: "a", b: {sub: "c"}});`,
		"subnum":      `api.authentication.setActor({sub: 1});`,
	} {
		_, err := h.cte("t1", name, `api.authentication.setUserById("u");`+body, nil)
		if !errors.Is(err, actions.ErrInvalidCommand) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestCTEEventShape(t *testing.T) {
	h := newHarness(t)
	const body = `api.authentication.setUserById("u"); api.user.setAppMetadata("ev", event);`
	n := 0
	ev := func(edit func(*actions.TokenExchangeInput)) map[string]any {
		t.Helper()
		n++
		r, err := h.cte("t1", fmt.Sprint("event", n), body, edit)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := r.AppMetadata["ev"].(map[string]any)
		return m
	}
	m := ev(nil)
	keys := func(v any) []string {
		var out []string
		for k := range v.(map[string]any) {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	if got := strings.Join(keys(m), ","); got != "client,request,resource_server,secrets,tenant,transaction" {
		t.Fatalf("event keys = %s", got)
	}
	req := m["request"].(map[string]any)
	if got := strings.Join(keys(req), ","); got != "body,geoip,hostname,ip,language,method,user_agent" && got != "body,hostname,ip,language,method,user_agent" {
		t.Fatalf("request keys = %s", got)
	}
	if b := req["body"].(map[string]any); len(b) != 0 {
		t.Fatalf("request.body must be empty: %v", b)
	}
	if req["ip"] != "198.51.100.1" || req["hostname"] != "t1.example.test" || req["method"] != "POST" || req["language"] != "en" || req["user_agent"] != "ua" {
		t.Fatalf("request = %v", req)
	}
	if c := m["client"].(map[string]any); c["client_id"] != "cli1" || c["name"] != "App" || c["metadata"] == nil {
		t.Fatalf("client = %v", c)
	}
	if m["resource_server"].(map[string]any)["identifier"] != "https://api.example.test/" || m["tenant"].(map[string]any)["id"] != "t1" {
		t.Fatalf("resource_server/tenant = %v %v", m["resource_server"], m["tenant"])
	}
	tx := m["transaction"].(map[string]any)
	if got := strings.Join(keys(tx), ","); got != "requested_scopes,requested_token_type,subject_token,subject_token_type" {
		t.Fatalf("transaction keys = %s", got)
	}
	if tx["subject_token"] != cteSubject || tx["subject_token_type"] != "https://example.test/legacy-token" ||
		tx["requested_token_type"] != "urn:ietf:params:oauth:token-type:access_token" || mustJSON(t, tx["requested_scopes"]) != `["read:a"]` {
		t.Fatalf("transaction = %v", tx)
	}

	// An actor token without a validated user carries no actor_token_user; an
	// organization appears only when the caller passes one.
	m = ev(func(in *actions.TokenExchangeInput) {
		in.ActorToken, in.ActorTokenType = cteActor, "urn:ietf:params:oauth:token-type:id_token"
		in.Organization = &store.Organization{ID: "org_1", Name: "acme", DisplayName: "Acme"}
	})
	tx = m["transaction"].(map[string]any)
	if tx["actor_token"] != cteActor || tx["actor_token_type"] != "urn:ietf:params:oauth:token-type:id_token" || tx["actor_token_user"] != nil {
		t.Fatalf("actor transaction = %v", tx)
	}
	if o := m["organization"].(map[string]any); o["id"] != "org_1" || o["name"] != "acme" {
		t.Fatalf("organization = %v", o)
	}
	m = ev(func(in *actions.TokenExchangeInput) {
		in.ActorToken, in.ActorTokenType = cteActor, "urn:ietf:params:oauth:token-type:id_token"
		in.ActorTokenUser = map[string]any{"user_id": "auth0|u2", "email": "u2@example.test"}
	})
	tx = m["transaction"].(map[string]any)
	if u, _ := tx["actor_token_user"].(map[string]any); u["user_id"] != "auth0|u2" {
		t.Fatalf("actor_token_user = %v", tx["actor_token_user"])
	}
	// ActorTokenUser without an actor token is ignored.
	m = ev(func(in *actions.TokenExchangeInput) { in.ActorTokenUser = map[string]any{"user_id": "x"} })
	if m["transaction"].(map[string]any)["actor_token_user"] != nil {
		t.Fatal("actor_token_user without an actor token")
	}
}

func TestCTETransactionMetadataUnsupported(t *testing.T) {
	h := newHarness(t)
	_, err := h.cte("t1", "txmeta", `api.authentication.setUserById("u"); api.transaction.setMetadata("k", "v");`, nil)
	if !errors.Is(err, actions.ErrUnsupported) {
		t.Fatalf("err = %v", err)
	}
	// Even a caught error fails the exchange.
	_, err = h.cte("t1", "txmeta2", `api.authentication.setUserById("u"); try { api.transaction.setMetadata("k", "v"); } catch {}`, nil)
	if !errors.Is(err, actions.ErrUnsupported) {
		t.Fatalf("caught: %v", err)
	}
}

func TestCTEOtherTriggersRefuseItsAPI(t *testing.T) {
	h := newHarness(t)
	a := h.action("t1", trigM2M, "wrongapi", `exports.onExecuteCredentialsExchange = async (event, api) => { api.authentication.setUserById("u"); };`, nil, false)
	h.bind("t1", trigM2M, a)
	_, err := h.eng.CredentialsExchange(context.Background(), h.m2mInput("t1"))
	var fe *actions.ErrFlow
	if !errors.As(err, &fe) || !errors.Is(err, actions.ErrActionError) {
		t.Fatalf("err = %v", err)
	}
}

func TestCTEActionMustBeDeployedCTEAction(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	in := h.cteInput("t1", "act_missing")
	if _, err := h.eng.CustomTokenExchange(ctx, in); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("missing: %v", err)
	}
	draft := h.action("t1", actions.TriggerCustomTokenExchange, "draftonly", `exports.onExecuteCustomTokenExchange = async () => {};`, nil, true)
	if _, err := h.eng.CustomTokenExchange(ctx, h.cteInput("t1", draft.ID)); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("undeployed: %v", err)
	}
	other := h.action("t1", trigLogin, "notcte", `exports.onExecutePostLogin = async () => {};`, nil, false)
	if _, err := h.eng.CustomTokenExchange(ctx, h.cteInput("t1", other.ID)); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("wrong trigger: %v", err)
	}
	// Tenant isolation: t2's Action is invisible to t1.
	foreign := h.action("t2", actions.TriggerCustomTokenExchange, "foreign", `exports.onExecuteCustomTokenExchange = async (e, api) => { api.authentication.setUserById("u"); };`, nil, false)
	if _, err := h.eng.CustomTokenExchange(ctx, h.cteInput("t1", foreign.ID)); !errors.Is(err, actions.ErrActionNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
}

func TestCTESubjectTokenMaskedInLogs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	a := h.action("t1", actions.TriggerCustomTokenExchange, "masked", `exports.onExecuteCustomTokenExchange = async (event, api) => {
	  console.log("subject", event.transaction.subject_token);
	  console.log("actor=" + event.transaction.actor_token);
	  console.log(JSON.stringify({again: "x" + event.transaction.subject_token + "y"}));
	  api.authentication.setUserById("u");
	  api.access.deny("denied", "no " + event.transaction.subject_token);
	};`, nil, false)
	in := h.cteInput("t1", a.ID)
	in.ActorToken, in.ActorTokenType = cteActor, "urn:ietf:params:oauth:token-type:id_token"
	r, err := h.eng.CustomTokenExchange(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Denied == nil || strings.Contains(r.Denied.Reason, cteSubject) || !strings.HasPrefix(r.Denied.Reason, "no ") {
		t.Fatalf("denial reason = %+v", r.Denied)
	}
	execs, err := h.st.Actions().ListExecutions(ctx, "t1", store.ExecutionFilter{})
	if err != nil || len(execs) != 1 {
		t.Fatalf("executions = %v %v", execs, err)
	}
	logs := strings.Join(execs[0].Results[0].Logs, "\n")
	if len(execs[0].Results[0].Logs) != 3 || strings.Contains(logs, cteSubject) || strings.Contains(logs, cteActor) || !strings.Contains(logs, customdb.Mask) {
		t.Fatalf("Action logs = %q", logs)
	}
	raw, _ := json.Marshal(execs)
	if strings.Contains(string(raw), cteSubject) || strings.Contains(string(raw), cteActor) {
		t.Fatalf("execution record leaks a token: %s", raw)
	}

	// The deny code is a printable string the Action chooses: a token used as
	// the code is refused and appears nowhere.
	c := h.action("t1", actions.TriggerCustomTokenExchange, "masked-code", `exports.onExecuteCustomTokenExchange = async (event, api) => {
	  api.authentication.setUserById("u");
	  api.access.deny(event.transaction.subject_token, "x");
	};`, nil, false)
	in = h.cteInput("t1", c.ID)
	r, err = h.eng.CustomTokenExchange(ctx, in)
	if !errors.Is(err, actions.ErrInvalidCommand) || r != nil {
		t.Fatalf("token as deny code: %+v %v", r, err)
	}
	if strings.Contains(err.Error(), cteSubject) || strings.Contains(h.logs.String(), cteSubject) {
		t.Fatalf("deny code leaked: %v\n%s", err, h.logs.String())
	}
	if strings.Contains(h.logs.String(), cteActor) {
		t.Fatal("actor token in server log")
	}

	// A failing Action's error and the server log are masked too.
	b := h.action("t1", actions.TriggerCustomTokenExchange, "masked-fail", `exports.onExecuteCustomTokenExchange = async (event) => {
	  throw new Error("failed for " + event.transaction.subject_token + " and " + event.transaction.actor_token);
	};`, nil, false)
	in = h.cteInput("t1", b.ID)
	in.ActorToken = cteActor
	_, err = h.eng.CustomTokenExchange(ctx, in)
	if err == nil || !errors.Is(err, actions.ErrActionError) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{err.Error(), h.logs.String()} {
		if strings.Contains(s, cteSubject) || strings.Contains(s, cteActor) {
			t.Fatalf("token leaked: %s", s)
		}
	}
}
