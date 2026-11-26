package mgmt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/cimd"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// cimdHost serves a Client ID Metadata Document whose keys can change.
type cimdHost struct {
	srv  *httptest.Server
	kid  atomic.Value // string
	doc  atomic.Value // func(url string) map[string]any
	key  *rsa.PrivateKey
	hits atomic.Int32
}

func newCIMDHost(t *testing.T) *cimdHost {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	h := &cimdHost{key: k}
	h.kid.Store("key-1")
	h.doc.Store(func(u string) map[string]any {
		return map[string]any{"client_id": u, "client_name": "Agent", "redirect_uris": []string{"https://agent.example/cb"},
			"token_endpoint_auth_method": "private_key_jwt", "jwks_uri": strings.TrimSuffix(u, "/client.json") + "/jwks"}
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/client.json", func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h.doc.Load().(func(string) map[string]any)("https://" + r.Host + "/client.json"))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{jose.JSONWebKey{Key: &h.key.PublicKey, KeyID: h.kid.Load().(string), Algorithm: "RS256", Use: "sig"}}})
	})
	h.srv = httptest.NewTLSServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

func (h *cimdHost) url() string { return h.srv.URL + "/client.json" }

func newCIMDEnv(t *testing.T) (*clientsEnv, *cimdHost) {
	e := newClientsEnv(t)
	h := newCIMDHost(t)
	pool := h.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	e.h.CIMD = &cimd.Registrar{Store: e.st, Fetcher: cimd.NewFetcher(federation.FixturePolicy(pool)), Now: e.h.Now}
	return e, h
}

func (e *clientsEnv) cimdCall(t *testing.T, caller mgmt.Caller, op string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	fn := e.h.PreviewCimdMetadata
	if op == "register" {
		fn = e.h.RegisterCimdClient
	}
	rec, out := e.call(t, e.tn, caller, "POST", "/api/v2/clients/cimd/"+op, body, fn)
	m, _ := out.(map[string]any)
	return rec, m
}

func countClients(t *testing.T, st store.Store, tenantID string) int {
	cs, _, err := st.Clients().List(context.Background(), tenantID, store.ClientFilter{}, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	return len(cs)
}

func TestCIMDPreview(t *testing.T) {
	e, h := newCIMDEnv(t)
	before := countClients(t, e.st, e.tn.ID)
	rec, out := e.cimdCall(t, m2mCaller("read:clients"), "preview", map[string]any{"external_client_id": h.url()})
	if rec.Code != 200 {
		t.Fatalf("preview %d %s", rec.Code, rec.Body)
	}
	v, _ := out["validation"].(map[string]any)
	mf, _ := out["mapped_fields"].(map[string]any)
	if v["valid"] != true || mf["name"] != "Agent" || mf["external_client_id"] != h.url() || mf["token_endpoint_auth_method"] != "private_key_jwt" || mf["app_type"] != "regular_web" {
		t.Fatalf("preview body %v", out)
	}
	creds := mf["client_authentication_methods"].(map[string]any)["private_key_jwt"].(map[string]any)["credentials"].([]any)
	if c := creds[0].(map[string]any); len(creds) != 1 || c["kid"] != "key-1" || c["alg"] != "RS256" || c["credential_type"] != "public_key" {
		t.Fatalf("credentials %v", creds)
	}
	if _, has := out["client_id"]; has || countClients(t, e.st, e.tn.ID) != before {
		t.Fatal("preview created a client")
	}
	// A form body works too.
	form := url.Values{"external_client_id": {h.url()}}.Encode()
	rec, _ = e.callWith(t, e.tn, m2mCaller("read:clients"), "POST", "/api/v2/clients/cimd/preview", form, http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, e.h.PreviewCimdMetadata)
	if rec.Code != 200 {
		t.Fatalf("form preview %d %s", rec.Code, rec.Body)
	}
	// A document that cannot be fetched: errors, no validation.
	rec, out = e.cimdCall(t, m2mCaller("read:clients"), "preview", map[string]any{"external_client_id": h.srv.URL + "/missing.json"})
	if errs, _ := out["errors"].([]any); rec.Code != 200 || len(errs) == 0 || out["validation"] != nil {
		t.Fatalf("unreachable %d %v", rec.Code, out)
	}
	// An invalid document: violations.
	h.doc.Store(func(string) map[string]any {
		return map[string]any{"client_id": "https://evil.example/client.json", "redirect_uris": []string{"https://a.example/cb"}}
	})
	_, out = e.cimdCall(t, m2mCaller("read:clients"), "preview", map[string]any{"external_client_id": h.url()})
	if v, _ := out["validation"].(map[string]any); v["valid"] != false || len(v["violations"].([]any)) == 0 {
		t.Fatalf("invalid document %v", out)
	}
	for _, body := range []any{map[string]any{"external_client_id": "http://agent.example/client.json"}, map[string]any{}, map[string]any{"external_client_id": h.url(), "x": 1}} {
		if rec, _ := e.cimdCall(t, m2mCaller("read:clients"), "preview", body); rec.Code != 400 {
			t.Errorf("%v: %d", body, rec.Code)
		}
	}
}

func TestCIMDRegister(t *testing.T) {
	e, h := newCIMDEnv(t)
	body := map[string]any{"external_client_id": h.url()}
	if rec, _ := e.cimdCall(t, m2mCaller("update:clients"), "register", body); rec.Code != 403 {
		t.Fatalf("create with update:clients only: %d", rec.Code)
	}
	if countClients(t, e.st, e.tn.ID) != 0 {
		t.Fatal("refused register created a client")
	}
	rec, out := e.cimdCall(t, m2mCaller("create:clients"), "register", body)
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	id, _ := out["client_id"].(string)
	if !strings.HasPrefix(id, "tpc_") || out["validation"].(map[string]any)["valid"] != true || out["mapped_fields"].(map[string]any)["callbacks"].([]any)[0] != "https://agent.example/cb" {
		t.Fatalf("create body %v", out)
	}
	c, err := e.st.Clients().Get(context.Background(), e.tn.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsFirstParty || c.ThirdPartySecurityMode != store.SecurityModeStrict || c.TokenEndpointAuthMethod != "" || len(c.Secrets) != 0 ||
		c.ExternalClientID() != h.url() || c.External.CreatedBy != store.ExternalCreatedByAdmin || len(c.PrivateKeyJWTCredentials) != 1 {
		t.Fatalf("stored %+v %+v", c, c.External)
	}
	first := c.PrivateKeyJWTCredentials[0]
	// The client view carries the external fields.
	rec, view := e.call(t, e.tn, m2mCaller("read:clients"), "GET", "/api/v2/clients/"+id, nil, func(w http.ResponseWriter, r *http.Request) { e.h.GetClient(w, r, id, mgmtapi.GetClientParams{}) })
	vm := view.(map[string]any)
	if rec.Code != 200 || vm["external_client_id"] != h.url() || vm["external_metadata_type"] != "cimd" || vm["external_metadata_created_by"] != "admin" || vm["external_metadata_status"] != "available" {
		t.Fatalf("view %d %v", rec.Code, vm)
	}

	// Updating needs update:clients and rotates the credentials to the document's.
	if rec, _ := e.cimdCall(t, m2mCaller("create:clients"), "register", body); rec.Code != 403 {
		t.Fatalf("update with create:clients only: %d", rec.Code)
	}
	h.kid.Store("key-2")
	rec, out = e.cimdCall(t, m2mCaller("update:clients"), "register", body)
	if rec.Code != 200 || out["client_id"] != id {
		t.Fatalf("update %d %v", rec.Code, out)
	}
	c, _ = e.st.Clients().Get(context.Background(), e.tn.ID, id)
	creds, _ := e.st.ClientCredentials().List(context.Background(), e.tn.ID, id)
	if len(creds) != 1 || creds[0].KID != "key-2" || c.PrivateKeyJWTCredentials[0] == first || c.PrivateKeyJWTCredentials[0] != creds[0].ID {
		t.Fatalf("rotation: %+v %v", creds, c.PrivateKeyJWTCredentials)
	}
	if countClients(t, e.st, e.tn.ID) != 1 {
		t.Fatal("update created a client")
	}

	// An invalid document is 400 and changes nothing.
	h.doc.Store(func(u string) map[string]any {
		return map[string]any{"client_id": u, "redirect_uris": []string{"https://a.example/cb"}, "client_secret": "x"}
	})
	if rec, _ := e.cimdCall(t, m2mCaller("update:clients"), "register", body); rec.Code != 400 {
		t.Fatalf("invalid document: %d %s", rec.Code, rec.Body)
	}
}

func TestCIMDRegisterConflictsWithDynamicClient(t *testing.T) {
	e, h := newCIMDEnv(t)
	if _, err := e.h.CIMD.Register(context.Background(), e.tn, h.url(), store.ExternalCreatedByClient, nil); err != nil {
		t.Fatal(err)
	}
	rec, _ := e.cimdCall(t, m2mCaller("create:clients", "update:clients"), "register", map[string]any{"external_client_id": h.url()})
	if rec.Code != http.StatusConflict {
		t.Fatalf("register over a dynamic client: %d %s", rec.Code, rec.Body)
	}
}

// Review Focus 4: concurrent registrations of one URL make one client.
func TestCIMDRegisterConcurrent(t *testing.T) {
	e, h := newCIMDEnv(t)
	fixed := func() time.Time { return now }
	e.h.Now, e.h.CIMD.Now = fixed, fixed // the env's ticking clock is not goroutine-safe
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec, _ := e.cimdCall(t, m2mCaller("create:clients", "update:clients"), "register", map[string]any{"external_client_id": h.url()})
			codes[i] = rec.Code
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == 201 {
			created++
		} else if c != 200 {
			t.Fatalf("codes %v", codes)
		}
	}
	if created != 1 || countClients(t, e.st, e.tn.ID) != 1 {
		t.Fatalf("codes %v, %d clients", codes, countClients(t, e.st, e.tn.ID))
	}
}
