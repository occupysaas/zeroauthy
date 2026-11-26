package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type resolveFixture struct {
	reg      *Registrar
	st       store.Store
	tn       *store.Tenant
	now      time.Time
	callback atomic.Value // string
	down     atomic.Bool
	url      string
	hits     atomic.Int32
}

func newResolveFixture(t *testing.T, settings map[string]any) *resolveFixture {
	t.Helper()
	f := &resolveFixture{now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
	f.callback.Store("https://agent.example/cb")
	mux := http.NewServeMux()
	mux.HandleFunc("/client.json", func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if f.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=600")
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "https://" + r.Host + "/client.json", "client_name": "Agent",
			"redirect_uris": []string{f.callback.Load().(string)}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	f.url = srv.URL + "/client.json"
	st := memory.New()
	t.Cleanup(func() { st.Close() })
	f.st = st
	f.tn = &store.Tenant{ID: "ten", Name: "ten", SettingsExtra: settings}
	if err := st.Tenants().Create(context.Background(), f.tn); err != nil {
		t.Fatal(err)
	}
	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	f.reg = &Registrar{Store: st, Fetcher: NewFetcher(federation.FixturePolicy(pool)), Now: func() time.Time { return f.now }}
	return f
}

var cimdOn = map[string]any{"client_id_metadata_document_supported": true}

func TestResolveLeavesOtherIDs(t *testing.T) {
	f := newResolveFixture(t, nil)
	// CIMD off: a URL is just an unknown client ID.
	if id, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil || id != f.url || f.hits.Load() != 0 {
		t.Fatalf("off: %q %v (%d fetches)", id, err, f.hits.Load())
	}
	f = newResolveFixture(t, cimdOn)
	if id, err := f.reg.Resolve(context.Background(), f.tn, "abc123"); err != nil || id != "abc123" {
		t.Fatalf("plain ID: %q %v", id, err)
	}
	// Unknown URL without dynamic registration: unchanged, nothing created.
	if id, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil || id != f.url || f.hits.Load() != 0 {
		t.Fatalf("unknown URL: %q %v", id, err)
	}
}

func TestResolveDynamicRegistration(t *testing.T) {
	f := newResolveFixture(t, map[string]any{"client_id_metadata_document_supported": true, "client_id_metadata_document_dynamic_registration_supported": true})
	id, err := f.reg.Resolve(context.Background(), f.tn, f.url)
	if err != nil || id == f.url {
		t.Fatalf("dynamic: %q %v", id, err)
	}
	c, err := f.st.Clients().Get(context.Background(), "ten", id)
	if err != nil || c.External.CreatedBy != store.ExternalCreatedByClient || c.ExternalClientID() != f.url || c.IsFirstParty || c.ThirdPartySecurityMode != store.SecurityModeStrict {
		t.Fatalf("created %+v %v", c, err)
	}
	// The second request finds it without fetching again.
	again, err := f.reg.Resolve(context.Background(), f.tn, f.url)
	if err != nil || again != id || f.hits.Load() != 1 {
		t.Fatalf("again: %q %v (%d fetches)", again, err, f.hits.Load())
	}
}

func TestResolveRefreshAndHardExpiry(t *testing.T) {
	f := newResolveFixture(t, cimdOn)
	out, err := f.reg.Register(context.Background(), f.tn, f.url, store.ExternalCreatedByAdmin, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := out.Client.ClientID
	callbacks := func() []string {
		c, err := f.st.Clients().Get(context.Background(), "ten", id)
		if err != nil {
			t.Fatal(err)
		}
		return c.Callbacks
	}
	// A changed document takes effect only after the cache expires.
	f.callback.Store("https://agent.example/new")
	f.now = f.now.Add(5 * time.Minute)
	if _, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil || callbacks()[0] != "https://agent.example/cb" {
		t.Fatalf("within max-age: %v %v", err, callbacks())
	}
	f.now = f.now.Add(6 * time.Minute)
	if _, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil || callbacks()[0] != "https://agent.example/new" {
		t.Fatalf("after max-age: %v %v", err, callbacks())
	}
	// Unreachable: still served, marked unavailable, until the hard expiry.
	f.down.Store(true)
	f.now = f.now.Add(time.Hour)
	if got, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil || got != id {
		t.Fatalf("soft failure: %q %v", got, err)
	}
	c, _ := f.st.Clients().Get(context.Background(), "ten", id)
	if c.External.Status != store.ExternalStatusUnavailable || callbacks()[0] != "https://agent.example/new" {
		t.Fatalf("status %q", c.External.Status)
	}
	f.now = f.now.Add(HardExpiry)
	if _, err := f.reg.Resolve(context.Background(), f.tn, f.url); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("past hard expiry: %v", err)
	}
	// Back up: available again.
	f.down.Store(false)
	if _, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil {
		t.Fatal(err)
	}
	c, _ = f.st.Clients().Get(context.Background(), "ten", id)
	if c.External.Status != store.ExternalStatusAvailable {
		t.Fatalf("recovered status %q", c.External.Status)
	}
}

// Final review: dynamic registration at /authorize is limited like
// /oidc/register, so unknown URLs cannot create clients or trigger fetches
// without bound.
func TestResolveDynamicRegistrationRateLimit(t *testing.T) {
	f := newResolveFixture(t, map[string]any{"client_id_metadata_document_supported": true, "client_id_metadata_document_dynamic_registration_supported": true})
	base := strings.TrimSuffix(f.url, "/client.json")
	limited := 0
	for i := range 8 {
		_, err := f.reg.Resolve(context.Background(), f.tn, fmt.Sprintf("%s/unknown-%d.json", base, i))
		if errors.Is(err, ErrRateLimited) {
			limited++
		}
	}
	if limited != 3 {
		t.Fatalf("%d of 8 unknown URLs limited, want 3 (burst 5)", limited)
	}
	// A known client is never limited.
	if _, err := f.reg.Register(context.Background(), f.tn, f.url, store.ExternalCreatedByAdmin, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.reg.Resolve(context.Background(), f.tn, f.url); err != nil {
		t.Fatalf("known client limited: %v", err)
	}
}
