package grpcstore

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestClientCredentialsCapabilityNegotiated(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	s, ok := any(c).(store.ClientCredentialsSupporter)
	if !ok {
		t.Fatal("client has no client_credentials.v1 probe")
	}
	if err := s.CheckClientCredentialsSupport(ctx); err != nil || !s.ClientCredentialsSupported() {
		t.Fatalf("client_credentials.v1 not negotiated: %v", err)
	}
	// The suite skips when the capability is missing, so assert it first: a
	// silent SKIP must never pass for coverage.
	if !store.ClientCredentialsAvailable(ctx, c) {
		t.Fatal("client credentials unavailable over gRPC against a capable store")
	}
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "ClientCredentials")
}

func TestClientCredentialsInTransaction(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "c", Name: "c"}); err != nil {
		t.Fatal(err)
	}
	cred := &store.ClientCredential{TenantID: "t", ClientID: "c", ID: "cred_" + "a123456789012345678901", Type: "public_key", Name: "k",
		KID: "kid-0123456789", Alg: "RS256", PublicKeyDER: []byte{1}, Thumbprint: "x"}
	exp := time.Now().Add(time.Hour)
	rollback := errors.New("rollback")
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.ClientCredentials().Create(ctx, cred, 2); err != nil {
			return err
		}
		if err := tx.ClientCredentials().UseJTI(ctx, "t", "c", "j1", exp); err != nil {
			return err
		}
		if err := tx.ClientCredentials().UseJTI(ctx, "t", "c", "j1", exp); !errors.Is(err, store.ErrConflict) {
			t.Errorf("replay in tx: %v", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("tx: %v", err)
	}
	if _, err := c.ClientCredentials().Get(ctx, "t", "c", cred.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("credential survived rollback: %v", err)
	}
	if err := c.ClientCredentials().UseJTI(ctx, "t", "c", "j1", exp); err != nil {
		t.Fatalf("jti survived rollback: %v", err)
	}
}

func TestClientCredentialsFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]*store.Client{
		"set": {TenantID: "t", ClientID: "a", Name: "a", PrivateKeyJWTCredentials: []string{"cred_1", "cred_2"},
			SignedRequestObject: &store.SignedRequestObject{Required: true, Credentials: []string{"cred_1"}}, TokenExchangeTypes: []string{"urn:x:y"}},
		"empty": {TenantID: "t", ClientID: "b", Name: "b", PrivateKeyJWTCredentials: []string{},
			SignedRequestObject: &store.SignedRequestObject{}, TokenExchangeTypes: []string{}},
		"unset": {TenantID: "t", ClientID: "c", Name: "c"},
	} {
		if err := c.Clients().Create(ctx, want); err != nil {
			t.Fatal(name, err)
		}
		got, err := c.Clients().Get(ctx, "t", want.ClientID)
		if err != nil {
			t.Fatal(name, err)
		}
		if !reflect.DeepEqual(got.PrivateKeyJWTCredentials, want.PrivateKeyJWTCredentials) ||
			!reflect.DeepEqual(got.SignedRequestObject, want.SignedRequestObject) ||
			!reflect.DeepEqual(got.TokenExchangeTypes, want.TokenExchangeTypes) {
			t.Fatalf("%s: client fields changed: %+v", name, got)
		}
	}
	rs := &store.ResourceServer{TenantID: "t", ID: "rs", Identifier: "https://api.test", Name: "api", SigningAlg: "HS256", SigningSecretSealed: []byte("sealed"), TokenLifetime: 60}
	if err := c.ResourceServers().Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ResourceServers().Get(ctx, "t", "rs"); err != nil || string(got.SigningSecretSealed) != "sealed" {
		t.Fatalf("signing secret: %+v %v", got, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	par := &store.PushedAuthRequest{TenantID: "t", IDHash: "h", ClientID: "a", Params: map[string]string{"a": "b"}, ExpiresAt: now.Add(time.Minute), CreatedAt: now, Signed: true}
	if err := c.PushedAuthRequests().Create(ctx, par); err != nil {
		t.Fatal(err)
	}
	if got, err := c.PushedAuthRequests().Get(ctx, "t", "h"); err != nil || !got.Signed {
		t.Fatalf("par signed: %+v %v", got, err)
	}
}

// A capable plugin is probed once: every later repository call, and the
// support check, reads the latch instead of issuing another capabilities RPC.
func TestClientCredentialsCapabilityProbedOnce(t *testing.T) {
	ctx := context.Background()
	faults := &eventsFaults{}
	c := serveEventsFaults(t, memory.New(), faults)
	cc := c.ClientCredentials()
	for range 3 {
		if _, err := cc.List(ctx, "t", "c"); err != nil {
			t.Fatal(err)
		}
		if _, err := cc.GetProfileByType(ctx, "t", "urn:x"); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if !store.ClientCredentialsAvailable(ctx, c) {
			t.Fatal("capable plugin reported unavailable")
		}
	}
	if got := faults.ccProbes.Load(); got != 1 {
		t.Fatalf("capability probes = %d, want 1", got)
	}
}

func TestClientCredentialsCapabilityAbsent(t *testing.T) {
	ctx := context.Background()
	faults := &eventsFaults{ccMissing: true}
	c := serveEventsFaults(t, memory.New(), faults)
	s := any(c).(store.ClientCredentialsSupporter)
	if s.ClientCredentialsSupported() || store.ClientCredentialsAvailable(ctx, c) {
		t.Fatal("old plugin reports client credentials support")
	}
	cc := c.ClientCredentials()
	jti := time.Now().Add(time.Minute)
	for name, err := range map[string]error{
		"create":      cc.Create(ctx, &store.ClientCredential{TenantID: "t", ClientID: "c", ID: "x"}, 2),
		"updateExp":   cc.UpdateExpiry(ctx, "t", "c", "x", nil),
		"delete":      cc.Delete(ctx, "t", "c", "x"),
		"useJTI":      cc.UseJTI(ctx, "t", "c", "j", jti),
		"createProf":  cc.CreateProfile(ctx, &store.TokenExchangeProfile{TenantID: "t", ID: "p"}, 100),
		"updateProf":  cc.UpdateProfile(ctx, &store.TokenExchangeProfile{TenantID: "t", ID: "p"}),
		"deleteProf":  cc.DeleteProfile(ctx, "t", "p"),
		"get":         second(cc.Get(ctx, "t", "c", "x")),
		"list":        second(cc.List(ctx, "t", "c")),
		"getProf":     second(cc.GetProfile(ctx, "t", "p")),
		"getProfType": second(cc.GetProfileByType(ctx, "t", "urn:x")),
		"purge":       second(cc.PurgeJTIs(ctx, jti, 10)),
		"forAction":   second(cc.ProfilesForAction(ctx, "t", "a")),
		"listProf":    third(cc.ListProfiles(ctx, "t", "", 10)),
	} {
		if !errors.Is(err, store.ErrClientCredentialsUnavailable) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The new fields are not sent, so the plugin never holds them.
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	cl := &store.Client{TenantID: "t", ClientID: "c", Name: "c", PrivateKeyJWTCredentials: []string{"cred_1"},
		SignedRequestObject: &store.SignedRequestObject{Required: true}, TokenExchangeTypes: []string{"urn:x:y"}}
	if err := c.Clients().Create(ctx, cl); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Clients().Get(ctx, "t", "c"); err != nil || got.PrivateKeyJWTCredentials != nil || got.SignedRequestObject != nil || got.TokenExchangeTypes != nil {
		t.Fatalf("client fields not dropped: %+v %v", got, err)
	}
	cl.Name = "renamed"
	if err := c.Clients().Update(ctx, cl); err != nil {
		t.Fatal(err)
	}
	rs := &store.ResourceServer{TenantID: "t", ID: "rs", Identifier: "https://api.test", Name: "api", SigningAlg: "HS256", SigningSecretSealed: []byte("sealed"), TokenLifetime: 60}
	if err := c.ResourceServers().Create(ctx, rs); err != nil {
		t.Fatal(err)
	}
	if got, err := c.ResourceServers().Get(ctx, "t", "rs"); err != nil || got.SigningSecretSealed != nil {
		t.Fatalf("signing secret not dropped: %+v %v", got, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if err := c.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{TenantID: "t", IDHash: "h", ClientID: "c", ExpiresAt: now.Add(time.Minute), CreatedAt: now, Signed: true}); err != nil {
		t.Fatal(err)
	}
	if got, err := c.PushedAuthRequests().Get(ctx, "t", "h"); err != nil || got.Signed {
		t.Fatalf("signed flag not dropped: %+v %v", got, err)
	}
	if faults.ccFieldsSent.Load() {
		t.Fatal("a Plan 35 field was sent to a plugin without client_credentials.v1")
	}
	// The latch holds, including inside a transaction.
	err := c.WithTx(ctx, func(tx store.Store) error { return tx.ClientCredentials().UseJTI(ctx, "t", "c", "j", jti) })
	if !errors.Is(err, store.ErrClientCredentialsUnavailable) {
		t.Fatalf("tx: %v", err)
	}
}

func TestClientCredentialsUseJTIOneWinnerOverGRPC(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.ClientCredentials().UseJTI(ctx, "t", "c", "same", exp)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else if !errors.Is(err, store.ErrConflict) {
				t.Errorf("loser: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("winners = %d", wins)
	}
}

func second[T any](_ T, err error) error        { return err }
func third[A, B any](_ A, _ B, err error) error { return err }
