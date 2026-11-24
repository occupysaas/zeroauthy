package adhub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

func TestTicketInfo(t *testing.T) {
	e := newEnv(t)
	ticket := e.ticket(e.ta, e.conn)
	if len(ticket) != ticketChars {
		t.Fatalf("ticket %q", ticket)
	}
	rec := httptest.NewRecorder()
	e.svc.TicketInfo(rec, request(e.ta, "GET", TicketPrefix+ticket+"/info", ""), ticket)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("info: %d %s", rec.Code, rec.Body)
	}
	var info struct {
		ADHub, ConnectionName, ConnectionDomain string
		CertAuth, Kerberos                      bool
		Realm                                   struct{ Name, PostTokenURL string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	realm, _ := raw["realm"].(map[string]any)
	if info.ADHub != "wss://acme.example.test/ad-hub" || info.ConnectionName != "corp" || info.ConnectionDomain != "corp.example.test" ||
		realm["name"] != "urn:auth0:acme:corp" || realm["postTokenUrl"] != "https://acme.example.test/login/callback" {
		t.Fatalf("info %s", rec.Body)
	}
	// Unknown tickets, and another tenant's ticket on this host, are 404:
	// the connector reports "Does this connection still exist?".
	for name, tc := range map[string]struct{ tn, ticketOf string }{
		"unknown": {"a", "nonsense"}, "other tenant": {"a", e.ticket(e.tb, e.connB)},
	} {
		rec := httptest.NewRecorder()
		e.svc.TicketInfo(rec, request(e.ta, "GET", TicketPrefix+tc.ticketOf+"/info", ""), tc.ticketOf)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func configure(t *testing.T, e *env, ticket, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	e.svc.TicketConfigure(rec, request(e.ta, "POST", TicketPrefix+ticket, body), ticket)
	return rec
}

func TestTicketConfigure(t *testing.T) {
	e := newEnv(t)
	ticket := e.ticket(e.ta, e.conn)
	k1, k2, k3 := newConnectorKey(t, 2048), newConnectorKey(t, 2048), newConnectorKey(t, 2048)
	body := func(k connectorKey) string {
		return `{"certs":["` + k.b64() + `"],"signInEndpoint":"http://connector.corp:4000/wsfed","agentMode":true,"agentVersion":"8.0.5"}`
	}
	rec := configure(t, e, ticket, body(k1))
	if rec.Code != http.StatusOK {
		t.Fatalf("configure: %d %s", rec.Code, rec.Body)
	}
	var out struct{ SigningKey string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.SigningKey) < 40 {
		t.Fatalf("signing key %q", out.SigningKey)
	}
	got, _ := e.st.Connections().Get(context.Background(), "ten_a", e.conn.ID)
	t1, _ := rules.ADFSThumbprints(k1.der)
	if c := anyStrings(got.Extra["certs"]); len(c) != 1 || c[0] != k1.b64() {
		t.Fatalf("certs %v", got.Extra["certs"])
	}
	if th := anyStrings(got.Extra["thumbprints"]); len(th) != 1 || th[0] != t1 || len(anyStrings(got.Extra["thumbprints_sha384"])) != 1 {
		t.Fatalf("thumbprints %v", got.Extra)
	}
	if got.Extra["signInEndpoint"] != "http://connector.corp:4000/wsfed" || got.Extra["agentMode"] != true || got.Extra["agentVersion"] != "8.0.5" ||
		got.Extra["tenant_domain"] != "corp.example.test" {
		t.Fatalf("options %v", got.Extra)
	}
	// The connector posts at every start (LR38a-4): the ticket stays valid,
	// the signing key is stable, and the two newest certificates are kept.
	for _, k := range []connectorKey{k1, k2, k3} {
		rec := configure(t, e, ticket, body(k))
		var again struct{ SigningKey string }
		_ = json.Unmarshal(rec.Body.Bytes(), &again)
		if rec.Code != http.StatusOK || again.SigningKey != out.SigningKey {
			t.Fatalf("repeat registration: %d %q", rec.Code, again.SigningKey)
		}
	}
	got, _ = e.st.Connections().Get(context.Background(), "ten_a", e.conn.ID)
	if c := anyStrings(got.Extra["certs"]); len(c) != 2 || c[0] != k3.b64() || c[1] != k2.b64() {
		t.Fatalf("kept certs %d", len(c))
	}
	// The other tenant's connection was not touched and keeps its own key.
	other, _ := e.st.Connections().Get(context.Background(), "ten_b", e.connB.ID)
	if other.Extra["certs"] != nil {
		t.Fatal("other tenant's connection changed")
	}
	keyB, err := e.svc.SigningKey(context.Background(), "ten_b", e.connB.ID)
	if err != nil || string(keyB) == out.SigningKey {
		t.Fatalf("signing keys must differ per connection: %v", err)
	}

	weak := newConnectorKey(t, 1024)
	for name, b := range map[string]string{
		"no certs":   `{}`,
		"two certs":  `{"certs":["` + k1.b64() + `","` + k2.b64() + `"]}`,
		"not a cert": `{"certs":["bm90IGEgY2VydA=="]}`,
		"weak key":   `{"certs":["` + weak.b64() + `"]}`,
		"endpoint":   `{"certs":["` + k1.b64() + `"],"signInEndpoint":"javascript:alert(1)"}`,
		"version":    `{"certs":["` + k1.b64() + `"],"agentVersion":"` + strings.Repeat("9", 33) + `"}`,
		"not json":   `certs`,
	} {
		if rec := configure(t, e, ticket, b); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	if rec := configure(t, e, "unknown", body(k1)); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown ticket: %d", rec.Code)
	}
}
