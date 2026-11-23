package mgmt_test

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/adhub"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func adEnv(t *testing.T) (*clientsEnv, *adhub.Service) {
	e := newClientsEnv(t)
	svc := &adhub.Service{Store: e.st, Wrapper: e.w, Now: func() time.Time { return now }}
	e.h.AD = svc
	return e, svc
}

// ad connections (Plan 38a): created with a provisioning ticket URL; the
// connector-managed options are ignored on writes (LR38a-6).
func TestADConnectionManagement(t *testing.T) {
	e, svc := adEnv(t)
	ctx := context.Background()
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp", "strategy": "ad",
		"options": map[string]any{"tenant_domain": "corp.example.test", "domain_aliases": []string{"corp.example.test"}, "ips": []string{"10.0.0.0/8"},
			"kerberos": true, "disable_self_service_change_password": true, "disable_cache": true,
			"certs": []string{"client-sent"}, "thumbprints": []string{"client-sent"}, "signInEndpoint": "https://evil.example.test/wsfed", "agentVersion": "9.9.9"}},
		e.h.CreateConnection)
	if r.Code != 201 {
		t.Fatalf("create: %d %v", r.Code, v)
	}
	view := v.(map[string]any)
	opts := view["options"].(map[string]any)
	for _, k := range []string{"certs", "thumbprints", "signInEndpoint", "agentVersion"} {
		if opts[k] != nil {
			t.Errorf("client-sent %s kept: %v", k, opts[k])
		}
	}
	if opts["brute_force_protection"] != true || opts["kerberos"] != true || opts["tenant_domain"] != "corp.example.test" {
		t.Fatalf("options %v", opts)
	}
	ticketURL, _ := view["provisioning_ticket_url"].(string)
	if !strings.HasPrefix(ticketURL, "https://login.acme.test/p/ad/") || len(ticketURL) < 40 {
		t.Fatalf("provisioning_ticket_url %q", ticketURL)
	}
	id := view["id"].(string)
	conn, err := e.st.Connections().Get(ctx, e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	// The connector registers: managed options are written by the ticket
	// route, not the Management API.
	block, _ := pem.Decode([]byte(samlTestCert(t)))
	storedCert := base64.StdEncoding.EncodeToString(block.Bytes)
	conn.Extra["certs"] = []any{storedCert}
	conn.Extra["signInEndpoint"] = "http://connector.corp:4000/wsfed"
	if err := e.st.Connections().Update(ctx, conn); err != nil {
		t.Fatal(err)
	}
	// An export re-imported (or any PATCH of options) keeps them.
	r, v = e.call(t, e.tn, m2mCaller(), "PATCH", "/connections/"+id, map[string]any{"options": map[string]any{"tenant_domain": "corp.example.test",
		"kerberos": false, "certs": []string{"replaced"}, "signInEndpoint": "https://evil.example.test/wsfed"}},
		func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, id) })
	if r.Code != 200 {
		t.Fatalf("update: %d %v", r.Code, v)
	}
	opts = v.(map[string]any)["options"].(map[string]any)
	if c, _ := opts["certs"].([]any); len(c) != 1 || c[0] != storedCert || opts["signInEndpoint"] != "http://connector.corp:4000/wsfed" || opts["kerberos"] != false {
		t.Fatalf("managed options after update %v", opts)
	}
	if v.(map[string]any)["provisioning_ticket_url"] != ticketURL {
		t.Fatal("ticket URL changed on update")
	}
	// GET and list carry the same URL.
	r, v = e.call(t, e.tn, m2mCaller(), "GET", "/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) {
		e.h.GetConnection(w, r, id, mgmtapi.GetConnectionParams{})
	})
	if r.Code != 200 || v.(map[string]any)["provisioning_ticket_url"] != ticketURL {
		t.Fatalf("get: %d %v", r.Code, v)
	}

	// Status: 404 "not connected to any node" until a connector session is
	// recorded, then 200.
	status := func() (int, any) {
		r, v := e.call(t, e.tn, m2mCaller(), "GET", "/connections/"+id+"/status", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionStatus(w, r, id) })
		return r.Code, v
	}
	if code, v := status(); code != 404 || !strings.Contains(fmt.Sprint(v), "not connected to any node") {
		t.Fatalf("offline status: %d %v", code, v)
	}
	repo, _ := store.ADHub(ctx, e.st)
	if err := repo.PutADHubSession(ctx, &store.ADHubSession{TenantID: e.tn.ID, ConnectionID: id, SessionID: "s1", ReplicaID: "r1", ConnectedAt: now, LastSeenAt: now}); err != nil {
		t.Fatal(err)
	}
	if code, v := status(); code != 200 {
		t.Fatalf("online status: %d %v", code, v)
	}
	// A stale session (its replica stopped heartbeating) is offline.
	svc.Now = func() time.Time { return now.Add(adhub.SessionLiveness + time.Second) }
	if code, _ := status(); code != 404 {
		t.Fatalf("stale session status: %d", code)
	}
	// Other strategies are never connected.
	if err := e.st.Connections().Create(ctx, &store.Connection{TenantID: e.tn.ID, ID: "con_db00000000000001", Name: "db", Strategy: "auth0"}); err != nil {
		t.Fatal(err)
	}
	r, _ = e.call(t, e.tn, m2mCaller(), "GET", "/status", nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetConnectionStatus(w, r, "con_db00000000000001") })
	if r.Code != 404 {
		t.Fatalf("database status: %d", r.Code)
	}
	// Deleting the connection deletes its ticket.
	r, _ = e.call(t, e.tn, m2mCaller(), "DELETE", "/connections/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.DeleteConnection(w, r, id) })
	if r.Code != 202 && r.Code != 204 {
		t.Fatalf("delete: %d", r.Code)
	}
	if _, err := repo.GetADProvisioning(ctx, e.tn.ID, id); err == nil {
		t.Fatal("ticket survived the connection")
	}
}

// Without the AD service (or ad_hub.v1) ad connections cannot be created.
func TestADConnectionUnavailable(t *testing.T) {
	e := newClientsEnv(t)
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp", "strategy": "ad"}, e.h.CreateConnection)
	if r.Code != http.StatusNotImplemented {
		t.Fatalf("create without AD service: %d %v", r.Code, v)
	}
}

// passwordAD records ChangePassword calls and answers with err.
type passwordAD struct {
	*adhub.Service
	got []string
	err error
}

func (p *passwordAD) ChangePassword(_ context.Context, _ *store.Connection, username, password string) error {
	p.got = append(p.got, username+":"+password)
	return p.err
}

// An ad user's password changes in the directory through a connector
// (Plan 38a); zeroauthy stores nothing.
func TestADUserPasswordChange(t *testing.T) {
	e, svc := adEnv(t)
	stub := &passwordAD{Service: svc}
	e.h.AD = stub
	ctx := context.Background()
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp", "strategy": "ad"}, e.h.CreateConnection)
	if r.Code != 201 {
		t.Fatalf("create: %d %v", r.Code, v)
	}
	users := map[string]map[string]any{"ad|corp|guid1": {"ad_username": "jdoe"}, "ad|corp|guid2": {}}
	for id, pd := range users {
		if err := e.st.Users().Create(ctx, &store.User{TenantID: e.tn.ID, UserID: id, Email: "j@corp.example", CreatedAt: now, UpdatedAt: now,
			Identities: []store.Identity{{Connection: "corp", Provider: "ad", UserID: strings.TrimPrefix(id, "ad|"), ProviderData: pd}}}); err != nil {
			t.Fatal(err)
		}
	}
	patch := func(id string, body map[string]any) (int, any) {
		r, v := e.call(t, e.tn, m2mCaller("update:users"), "PATCH", "/users/"+id, body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateUser(w, r, id) })
		return r.Code, v
	}
	if code, v := patch("ad|corp|guid1", map[string]any{"password": "N3w-Directory-Pw!", "connection": "corp"}); code != 200 {
		t.Fatalf("change: %d %v", code, v)
	}
	if len(stub.got) != 1 || stub.got[0] != "jdoe:N3w-Directory-Pw!" {
		t.Fatalf("connector request %v", stub.got)
	}
	for name, tc := range map[string]struct {
		id   string
		body map[string]any
		err  error
		code int
	}{
		"with other fields": {"ad|corp|guid1", map[string]any{"password": "x", "email": "n@corp.example"}, nil, 400},
		"never signed in":   {"ad|corp|guid2", map[string]any{"password": "x"}, nil, 400},
		"directory refuses": {"ad|corp|guid1", map[string]any{"password": "x"}, adhub.ErrPasswordRejected, 400},
		"no connector":      {"ad|corp|guid1", map[string]any{"password": "x"}, adhub.ErrUnavailable, 503},
	} {
		stub.err = tc.err
		if code, v := patch(tc.id, tc.body); code != tc.code {
			t.Errorf("%s: %d %v", name, code, v)
		}
	}
}
