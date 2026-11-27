package server

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// cibaFlowSeed adds the CIBA backend and bob to the flow tenant.
var cibaFlowSeed = strings.Replace(flowSeed, `    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true, enabled_clients: [spa, tv, spa2]}
    users:
      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}`,
	`      - {client_id: agent, name: "Agent backend", app_type: regular_web, client_secret: agent-secret, grant_types: [authorization_code, "urn:openid:params:grant-type:ciba"], async_approval_notification_channels: [email]}
    connections:
      - {name: Username-Password-Authentication, is_domain_connection: true, enabled_clients: [spa, tv, spa2, agent]}
    users:
      - {connection: Username-Password-Authentication, email: alice@flow.test, password: "alice password 1", email_verified: true}
      - {connection: Username-Password-Authentication, email: bob@flow.test, password: "bob password 22", email_verified: true}`, 1)

type mailCapture struct{ msgs chan email.Message }

func (m mailCapture) Send(_ context.Context, msg email.Message) error {
	m.msgs <- msg
	return nil
}

var consentLink = regexp.MustCompile(`href="(https://[^"]+/bc-verify\?consent=[^"]+)"`)

type cibaEnv struct {
	*flowEnv
	mail mailCapture
}

func newCIBAEnv(t *testing.T) *cibaEnv {
	if !strings.Contains(cibaFlowSeed, "agent-secret") {
		t.Fatal("seed rewrite failed")
	}
	mail := mailCapture{msgs: make(chan email.Message, 16)}
	e := newFlowEnvSeed(t, cibaFlowSeed, func(d *Deps) { d.Mailer = mail })
	return &cibaEnv{flowEnv: e, mail: mail}
}

func (e *cibaEnv) userID(t *testing.T, mail string) string {
	tn, _ := e.st.Tenants().GetByName(context.Background(), "flow")
	us, err := e.st.Users().FindByEmail(context.Background(), tn.ID, mail)
	if err != nil || len(us) == 0 {
		t.Fatalf("user %s: %v", mail, err)
	}
	return us[0].UserID
}

// start creates a request for mail's user and returns its auth_req_id and
// the emailed link.
func (e *cibaEnv) start(t *testing.T, c *http.Client, user string) (string, string) {
	t.Helper()
	hint := `{"format":"iss_sub","iss":"` + e.base + `/","sub":"` + e.userID(t, user) + `"}`
	resp, out := e.postForm(t, c, "/bc-authorize", url.Values{"client_id": {"agent"}, "client_secret": {"agent-secret"}, "scope": {"openid email"},
		"login_hint": {hint}, "binding_message": {"ORDER-42"}, "requested_expiry": {"600"}})
	if resp.StatusCode != 200 {
		t.Fatalf("bc-authorize %d %v", resp.StatusCode, out)
	}
	select {
	case m := <-e.mail.msgs:
		link := consentLink.FindStringSubmatch(m.HTML)
		if m.To != user || link == nil || !strings.Contains(m.HTML, "ORDER-42") {
			t.Fatalf("mail %+v", m)
		}
		return out["auth_req_id"].(string), strings.ReplaceAll(link[1], "&amp;", "&")
	case <-time.After(5 * time.Second):
		t.Fatal("no approval email")
	}
	return "", ""
}

func (e *cibaEnv) status(t *testing.T, id string) store.CIBAStatus {
	tn, _ := e.st.Tenants().GetByName(context.Background(), "flow")
	r, err := e.st.(store.CIBAStore).GetCIBARequest(context.Background(), tn.ID, secrets.HashToken(id))
	if err != nil {
		t.Fatal(err)
	}
	return r.Status
}

func (e *cibaEnv) post(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, string) {
	req, _ := http.NewRequest("POST", e.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return mustDo(t, c, req)
}

// decide opens link and posts action; it returns the redirect.
func (e *cibaEnv) decide(t *testing.T, c *http.Client, link, action string) *url.URL {
	t.Helper()
	resp, page := fetch(t, c, link)
	if resp.StatusCode != 200 || !strings.Contains(page, "ORDER-42") || !strings.Contains(page, "Agent backend") {
		t.Fatalf("approval page %d\n%s", resp.StatusCode, page)
	}
	state := regexp.MustCompile(`name="state" value="([^"]+)"`).FindStringSubmatch(page)[1]
	resp, _ = e.post(t, c, "/bc-verify", url.Values{"state": {state}, "csrf": {csrfRe.FindStringSubmatch(page)[1]}, "action": {action}})
	loc, _ := resp.Location()
	if resp.StatusCode != 302 || loc == nil {
		t.Fatalf("decision %d %v", resp.StatusCode, loc)
	}
	return loc
}

// login signs in on the login page at loc and returns the next response.
func (e *cibaEnv) login(t *testing.T, c *http.Client, loc *url.URL, user, password string) (*http.Response, string) {
	t.Helper()
	if loc.Path != "/u/login" {
		t.Fatalf("expected the login page, got %v", loc)
	}
	_, page := fetch(t, c, e.base+loc.RequestURI())
	return e.post(t, c, "/u/login", url.Values{"hosted_revision": {hostedRevision(page)}, "state": {loc.Query().Get("state")}, "csrf": {csrfRe.FindStringSubmatch(page)[1]},
		"username": {user}, "password": {password}})
}

// Review Focus 2: a session of bob opening alice's link must sign in as
// alice; signing in as bob decides nothing.
func TestApprovalRequiresHintedUser(t *testing.T) {
	e := newCIBAEnv(t)
	c := e.client(t)
	e.codeFlowAs(t, c, "bob@flow.test", "bob password 22") // the browser holds bob's session
	id, link := e.start(t, c, "alice@flow.test")
	loc := e.decide(t, c, link, "approve")
	if loc.Path != "/u/login" {
		t.Fatalf("bob's session was reused: %v", loc)
	}
	resp, page := e.login(t, c, loc, "bob@flow.test", "bob password 22")
	if resp.StatusCode != 400 || !strings.Contains(page, "Sign in as the user this request is for") {
		t.Fatalf("approval as bob: %d\n%s", resp.StatusCode, page)
	}
	if s := e.status(t, id); s != store.CIBAPending {
		t.Fatalf("status after bob = %s", s)
	}
	loc = e.decide(t, c, link, "approve")
	resp, _ = e.login(t, c, loc, "alice@flow.test", "alice password 1")
	next, _ := resp.Location()
	if resp.StatusCode != 302 || next == nil || next.Path != "/bc-verify/approved" {
		t.Fatalf("approval as alice: %d %v", resp.StatusCode, next)
	}
	if s := e.status(t, id); s != store.CIBAApproved {
		t.Fatalf("status = %s", s)
	}
	if resp, page := fetch(t, c, e.base+"/bc-verify/approved"); resp.StatusCode != 200 || !strings.Contains(page, "Request approved") {
		t.Fatalf("approved page %d", resp.StatusCode)
	}
	// The link is spent once the request is decided.
	if resp, page := fetch(t, c, link); resp.StatusCode != 400 || !strings.Contains(page, "expired") {
		t.Fatalf("spent link %d\n%s", resp.StatusCode, page)
	}
	// alice's session now approves the next request without a login.
	id2, link2 := e.start(t, c, "alice@flow.test")
	if loc := e.decide(t, c, link2, "approve"); loc.Path != "/bc-verify/approved" {
		t.Fatalf("session reuse: %v", loc)
	}
	if s := e.status(t, id2); s != store.CIBAApproved {
		t.Fatalf("status = %s", s)
	}
}

func TestApprovalDeny(t *testing.T) {
	e := newCIBAEnv(t)
	c := e.client(t)
	id, link := e.start(t, c, "alice@flow.test")
	if loc := e.decide(t, c, link, "deny"); loc.Path != "/bc-verify/denied" {
		t.Fatalf("deny: %v", loc)
	}
	if s := e.status(t, id); s != store.CIBADenied {
		t.Fatalf("status = %s", s)
	}
	if resp, _ := fetch(t, c, e.base+"/bc-verify?consent=not-a-real-value"); resp.StatusCode != 400 {
		t.Fatalf("unknown link %d", resp.StatusCode)
	}
}

// The whole flow over HTTP: /bc-authorize, the emailed link, approval as
// the user, and the poll that redeems the tokens once.
func TestCIBAEndToEnd(t *testing.T) {
	e := newCIBAEnv(t)
	c := e.client(t)
	id, link := e.start(t, c, "alice@flow.test")
	poll := func() (*http.Response, map[string]any) {
		return e.postForm(t, c, "/oauth/token", url.Values{"grant_type": {"urn:openid:params:grant-type:ciba"}, "client_id": {"agent"}, "client_secret": {"agent-secret"}, "auth_req_id": {id}})
	}
	if resp, out := poll(); resp.StatusCode != 400 || out["error"] != "authorization_pending" {
		t.Fatalf("pending: %d %v", resp.StatusCode, out)
	}
	loc := e.decide(t, c, link, "approve")
	resp, _ := e.login(t, c, loc, "alice@flow.test", "alice password 1")
	if next, _ := resp.Location(); next == nil || next.Path != "/bc-verify/approved" {
		t.Fatalf("approval ended at %v", next)
	}
	// The pending poll started the 5-second interval; poll after it.
	time.Sleep(5100 * time.Millisecond)
	resp, tok := poll()
	if resp.StatusCode != 200 || tok["id_token"] == nil || tok["access_token"] == nil {
		t.Fatalf("tokens: %d %v", resp.StatusCode, tok)
	}
	time.Sleep(5100 * time.Millisecond)
	if resp, out := poll(); resp.StatusCode != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("second poll: %d %v", resp.StatusCode, out)
	}
}
