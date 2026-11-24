package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/net/websocket"

	"github.com/zeroauthy/zeroauthy/internal/adhub"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const adSignIn = "https://connector.flow.test/wsfed"

// adEnv is the flow server with the AD/LDAP service and an ad connection
// enabled for spa (provisioned like the Management API does).
func adEnv(t *testing.T, opts map[string]any) (*flowEnv, *store.Tenant, *store.Connection, *adhub.Service) {
	t.Helper()
	var svc *adhub.Service
	e := newFlowEnvSeed(t, flowSeed, func(d *Deps) {
		d.Federation = &federation.FlowService{Service: federation.Service{Wrapper: d.Wrapper}, Store: d.Store,
			Providers: federation.NewProviders(federation.NetworkPolicy{}, time.Now)}
		svc = &adhub.Service{Store: d.Store, Wrapper: d.Wrapper}
		svc.Hub = &adhub.Hub{Service: svc, ReplicaID: "test"}
		d.AD = svc
	})
	ctx := context.Background()
	tn, err := e.st.Tenants().GetByName(ctx, "flow")
	if err != nil {
		t.Fatal(err)
	}
	if tn.CanonicalHost == "" {
		tn.CanonicalHost = tn.Domains[0]
		if err := e.st.Tenants().Update(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	conn := &store.Connection{TenantID: tn.ID, ID: "con_ad0123456789abcd", Name: "corp-ad", Strategy: "ad", Extra: opts,
		EnabledClients: []string{"spa"}, FederationRevision: 1, BruteForceProtection: true}
	err = e.st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Connections().Create(ctx, conn); err != nil {
			return err
		}
		return svc.Provision(ctx, tx, conn)
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, tn, conn, svc
}

// TestADConnectorEndToEnd drives the real router: ticket information and
// registration, the hub socket with the connector's token, and a password
// login answered over the socket.
func TestADConnectorEndToEnd(t *testing.T) {
	e, tn, conn, svc := adEnv(t, map[string]any{"tenant_domain": "corp.flow.test"})
	ctx := context.Background()
	host := strings.TrimPrefix(e.base, "https://")
	ticketURL, err := svc.TicketURL(ctx, host, conn)
	if err != nil {
		t.Fatal(err)
	}
	c := e.client(t)
	resp, body := fetch(t, c, ticketURL+"/info")
	var info map[string]any
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &info) != nil || info["adHub"] != "wss://"+host+"/ad-hub" || info["connectionName"] != "corp-ad" {
		t.Fatalf("ticket info: %d %s", resp.StatusCode, body)
	}
	idp := newFixtureIdP(t) // the connector's key pair
	reg, _ := json.Marshal(map[string]any{"certs": []string{base64.StdEncoding.EncodeToString(idp.cert.Raw)}, "signInEndpoint": adSignIn, "agentMode": true, "agentVersion": "8.0.5"})
	req, _ := http.NewRequest("POST", ticketURL, strings.NewReader(string(reg)))
	req.Header.Set("Content-Type", "application/json")
	resp, body = mustDo(t, c, req)
	var out struct{ SigningKey string }
	if resp.StatusCode != 200 || json.Unmarshal([]byte(body), &out) != nil || out.SigningKey == "" {
		t.Fatalf("register: %d %s", resp.StatusCode, body)
	}

	// The connector's socket, through the server's router and middleware.
	cfg, _ := websocket.NewConfig("wss://"+host+"/ad-hub", "https://connector.invalid")
	cfg.TlsConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test server
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: idp.key}, nil)
	tok, _ := jwt.Signed(signer).Claims(jwt.Claims{Issuer: "corp-ad", Audience: jwt.Audience{"urn:auth0:flow:corp-ad"}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Minute))}).Serialize()
	auth, _ := json.Marshal(map[string]any{"n": "authenticate", "p": map[string]any{"jwt": tok}})
	if _, err := ws.Write(auth); err != nil {
		t.Fatal(err)
	}
	var first []byte
	if err := websocket.Message.Receive(ws, &first); err != nil || string(first) != `{"n":"authenticated"}` {
		t.Fatalf("hub answer %s %v", first, err)
	}
	go func() {
		for {
			var raw []byte
			if websocket.Message.Receive(ws, &raw) != nil {
				return
			}
			var f struct {
				N string
				P struct{ JWT string }
			}
			_ = json.Unmarshal(raw, &f)
			parsed, err := jwt.ParseSigned(f.P.JWT, []jose.SignatureAlgorithm{jose.HS256})
			if err != nil {
				continue
			}
			claims := map[string]any{}
			if parsed.Claims([]byte(out.SigningKey), &claims) != nil {
				continue
			}
			reply := map[string]any{"err": map[string]any{"name": "WrongPassword"}}
			if claims["username"] == "jdoe" && claims["password"] == "Directory-Pw-1" {
				reply = map[string]any{"profile": map[string]any{"id": "guid-jdoe", "displayName": "John Doe", "emails": []any{map[string]any{"value": "jdoe@corp.flow.test"}}, "groups": []string{"users"}}}
			}
			b, _ := json.Marshal(map[string]any{"n": claims["pid"].(string) + "_result", "p": reply})
			_, _ = ws.Write(b)
		}
	}()
	waitOnline := time.Now().Add(5 * time.Second)
	for !svc.Hub.Connected(tn.ID, conn.ID) {
		if time.Now().After(waitOnline) {
			t.Fatal("connector not attached")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The hosted login of spa with connection=corp-ad.
	resp, _ = fetch(t, c, authorizeURL(e.base, "connection", "corp-ad"))
	loc, _ := resp.Location()
	resp, page := fetch(t, c, e.base+loc.RequestURI())
	m := csrfRe.FindStringSubmatch(page)
	if resp.StatusCode != 200 || m == nil || !strings.Contains(page, `name="password"`) {
		t.Fatalf("login page: %d %s", resp.StatusCode, page)
	}
	post := func(password string) *http.Response {
		form := url.Values{"state": {loc.Query().Get("state")}, "csrf": {m[1]}, "username": {"jdoe"}, "password": {password}}
		if rev := hostedRevisionRe.FindStringSubmatch(page); rev != nil {
			form.Set("hosted_revision", rev[1])
		}
		req, _ := http.NewRequest("POST", e.base+"/u/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, body := mustDo(t, c, req)
		page = body // a failed attempt renders the form again with a new revision
		return resp
	}
	if resp := post("wrong"); resp.StatusCode != 401 {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	if m = csrfRe.FindStringSubmatch(page); m == nil {
		t.Fatal("no form after the failed attempt")
	}
	if resp := post("Directory-Pw-1"); !completed(t, e, c, resp) {
		t.Fatalf("ad login did not reach the application: %d", resp.StatusCode)
	}
	u, err := e.st.Users().Get(ctx, tn.ID, "ad|corp-ad|guid-jdoe")
	if err != nil || u.Name != "John Doe" || u.Email != "jdoe@corp.flow.test" {
		t.Fatalf("user %+v %v", u, err)
	}
}

// Kerberos (Plan 38a §5): from a listed range the login goes to the
// connector's WS-Fed endpoint and its signed token returns to
// /login/callback; the user is the one password logins create.
func TestADKerberosLogin(t *testing.T) {
	idp := newFixtureIdP(t)
	e, tn, _, _ := adEnv(t, map[string]any{"kerberos": true, "ips": []any{"127.0.0.0/8", "::1/128"}, "signInEndpoint": adSignIn,
		"certs": []any{base64.StdEncoding.EncodeToString(idp.cert.Raw)}})
	c := e.client(t)
	resp, _ := fetch(t, c, authorizeURL(e.base, "connection", "corp-ad"))
	var q url.Values
	for i := 0; i < 5 && (resp.StatusCode == 302 || resp.StatusCode == 303); i++ {
		loc, _ := resp.Location()
		if loc.Host == "connector.flow.test" {
			q = loc.Query()
			break
		}
		resp, _ = fetch(t, c, e.base+loc.RequestURI())
	}
	if q == nil {
		t.Fatalf("login did not reach the connector (status %d)", resp.StatusCode)
	}
	if q.Get("wa") != "wsignin1.0" || q.Get("wtrealm") != "urn:auth0:flow:corp-ad" || q.Get("wreply") != e.base+"/login/callback" || q.Get("wctx") == "" {
		t.Fatalf("sign-in request %v", q)
	}
	now := time.Now()
	signed, err := samlcore.Signer{Key: idp.key, Cert: idp.cert}.SignEnveloped11(samlcore.BuildAssertion11(samlcore.Assertion11Spec{
		ID: "_k1", Issuer: "corp.flow.test", NameID: "guid-jdoe", Audience: "urn:auth0:flow:corp-ad", IssueInstant: now,
		NotBefore: now.Add(-time.Minute), NotOnOrAfter: now.Add(time.Hour), AuthnInstant: now,
		Attributes: []samlcore.Attribute{{Name: samlcore.ClaimEmail, Values: []string{"jdoe@corp.flow.test"}}, {Name: samlcore.ClaimName, Values: []string{"John Doe"}}}}))
	if err != nil {
		t.Fatal(err)
	}
	wresult, err := samlcore.BuildRSTR(q.Get("wctx"), signed)
	if err != nil {
		t.Fatal(err)
	}
	if resp := postWResult(t, e, c, wresult, q.Get("wctx")); !completed(t, e, c, resp) {
		t.Fatalf("kerberos callback did not complete: %d", resp.StatusCode)
	}
	if _, err := e.st.Users().Get(context.Background(), tn.ID, "ad|corp-ad|guid-jdoe"); err != nil {
		t.Fatal(err)
	}

	// Outside the ranges: the username/password form.
	e2, _, _, _ := adEnv(t, map[string]any{"kerberos": true, "ips": []any{"10.0.0.0/8"}, "signInEndpoint": adSignIn,
		"certs": []any{base64.StdEncoding.EncodeToString(idp.cert.Raw)}})
	c2 := e2.client(t)
	resp, _ = fetch(t, c2, authorizeURL(e2.base, "connection", "corp-ad"))
	loc, _ := resp.Location()
	resp, page := fetch(t, c2, e2.base+loc.RequestURI())
	if resp.StatusCode != 200 || !strings.Contains(page, `name="password"`) {
		t.Fatalf("outside the ranges: %d", resp.StatusCode)
	}
}
