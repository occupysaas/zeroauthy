package grpcstore

import (
	"context"
	"errors"
	"github.com/google/go-cmp/cmp"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// Old protocols must reject populated fields before silently dropping their
// origin/canonical identity. Each case also covers rotation's replacement row.
func TestOldPluginRejectsOriginWrites(t *testing.T) {
	c := serveOldPlugin(t)
	defer c.Close()
	ctx := context.Background()
	cases := map[string]func() error{
		"tenant-create": func() error { return c.Tenants().Create(ctx, &store.Tenant{CanonicalHost: "canonical.example"}) },
		"tenant-update": func() error { return c.Tenants().Update(ctx, &store.Tenant{CanonicalHost: "canonical.example"}) },
		"session":       func() error { return c.Sessions().Create(ctx, &store.LoginSession{Origin: "https://login.example"}) },
		"transaction": func() error {
			return c.AuthTransactions().Create(ctx, &store.AuthTransaction{Origin: "https://login.example"})
		},
		"code": func() error { return c.AuthCodes().Create(ctx, &store.AuthCode{Origin: "https://login.example"}) },
		"par": func() error {
			return c.PushedAuthRequests().Create(ctx, &store.PushedAuthRequest{Origin: "https://login.example"})
		},
		"device": func() error { return c.DeviceCodes().Create(ctx, &store.DeviceCode{Origin: "https://login.example"}) },
		"refresh": func() error {
			return c.RefreshTokens().Create(ctx, &store.RefreshToken{Origin: "https://login.example"})
		},
		"rotate": func() error {
			return c.RefreshTokens().Rotate(ctx, "t", "old", &store.RefreshToken{Origin: "https://login.example"}, time.Now(), 0)
		},
		"reset": func() error {
			return c.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{Origin: "https://login.example"})
		},
		"verify": func() error {
			return c.EmailVerificationTickets().Create(ctx, &store.EmailVerificationTicket{Origin: "https://login.example"})
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if e := call(); !errors.Is(e, store.ErrCustomDomainRepositoryUnavailable) {
				t.Fatalf("origin write error = %v", e)
			}
		})
	}
}

func TestCustomDomainCapabilityErrorsRoundTrip(t *testing.T) {
	for _, want := range []error{store.ErrCustomDomainRepositoryUnavailable, store.ErrTLSAssetRepositoryUnavailable} {
		if got := errFromPB(errToPB(want)); !errors.Is(got, want) {
			t.Fatalf("%v round trip = %v", want, got)
		}
	}
}

// A CheckLease guard must remain attached to the actual server transaction,
// survive a successful savepoint, and disappear with a failed savepoint.
func TestTLSLeaseTransactionCompletion(t *testing.T) {
	for _, driver := range []struct {
		name string
		open func(*testing.T) *Client
	}{{"memory", inProcess}, {"sqlite", inProcessSQLite}} {
		t.Run(driver.name, func(t *testing.T) {
			for _, mode := range []string{"root", "child-commit", "child-rollback"} {
				t.Run(mode, func(t *testing.T) {
					c := driver.open(t)
					defer c.Close()
					ctx := context.Background()
					l, e := c.TLSAssets().ClaimLease(ctx, "resource", "worker", 500*time.Millisecond)
					if e != nil {
						t.Fatal(e)
					}
					aborted := errors.New("savepoint rollback")
					e = c.WithTx(ctx, func(tx store.Store) error {
						checked := func(v store.Store) error {
							if e := v.TLSAssets().CheckLease(ctx, *l); e != nil {
								return e
							}
							if mode == "child-rollback" {
								return aborted
							}
							return nil
						}
						if mode == "root" {
							if e := checked(tx); e != nil {
								return e
							}
						} else {
							e := tx.WithTx(ctx, checked)
							if mode == "child-rollback" {
								if !errors.Is(e, aborted) {
									return e
								}
							} else if e != nil {
								return e
							}
						}
						if e := tx.TLSAssets().Put(ctx, &store.TLSAsset{Key: "published", Kind: store.TLSAssetCertificate, Ciphertext: []byte("opaque-sealed")}, 0); e != nil {
							return e
						}
						time.Sleep(time.Until(l.Until) + 30*time.Millisecond)
						return nil
					})
					wantErr := store.ErrConflict
					if mode == "child-rollback" {
						wantErr = nil
					}
					if !errors.Is(e, wantErr) {
						t.Fatalf("completion = %v, want %v", e, wantErr)
					}
					_, e = c.TLSAssets().Get(ctx, "published")
					if mode == "child-rollback" {
						if e != nil {
							t.Fatal(e)
						}
					} else if !errors.Is(e, store.ErrNotFound) {
						t.Fatalf("expired lease published: %v", e)
					}
				})
			}
		})
	}
}

// Every private field crosses a real protobuf wire. The reflective guard makes
// future model additions fail until the protocol fixtures exercise them too.
func TestPrivatePersistenceFullFields(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx := context.Background()
	if e := c.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}); e != nil {
		t.Fatal(e)
	}
	d := &store.CustomDomain{TenantID: "tenant", ID: "domain", Domain: "login.example", Type: "auth0_managed_certs", Source: "api", OriginHost: "cd-1.origin.example", Generation: 4, Revision: 1, Status: "ready", TLSPolicy: "managed", CustomClientIPHeader: "x-forwarded-for", CustomClientIPHeaderNull: true, RelyingPartyIdentifier: "example", DomainMetadata: map[string]string{"team": "blue"}, VerificationMethod: "txt", ProofRecordName: "_zeroauthy-domain-verification.login.example", ProofRecordValue: "proof", ProofStatus: "verified", ProofToken: []byte("proof-token"), ProofCreatedAt: nanoTime, ProofVerifiedAt: &nanoTime, LastProofCheckAt: &nanoTime, ProofFailureSince: &nanoTime, Lifecycle: "active", NextAttemptAt: &nanoTime, AttemptCount: 3, LastFailure: "diagnostic", ProxyKeyHash: []byte("hash"), ActiveCertificateKey: "cert", CreatedAt: nanoTime, UpdatedAt: nanoTime}
	assertNoZeroFields(t, "", reflect.ValueOf(d))
	d.Revision = 0
	if e := c.CustomDomains().Create(ctx, d); e != nil {
		t.Fatal(e)
	}
	got, e := c.CustomDomains().Get(ctx, "tenant", "domain")
	if e != nil {
		t.Fatal(e)
	}
	if diff := cmp.Diff(d, got); diff != "" {
		t.Fatalf("domain round trip (-want +got):\n%s", diff)
	}
	a := &store.TLSAsset{Key: "cert", Kind: store.TLSAssetCertificate, TenantID: "tenant", DomainID: "domain", Generation: 4, Revision: 1, Ciphertext: []byte("sealed-envelope"), PublicData: store.TLSPublicData{Version: 1, DirectoryURL: "https://ca.example/directory", AccountURL: "https://ca.example/account", OrderURL: "https://ca.example/order", Status: "valid", ChallengeType: "http-01", Identifier: "login.example", Token: "token", KeyAuthorization: "authorization", RecordName: "_acme-challenge.login.example", RecordValue: "dns", DNSRecordID: "record", CertificateChainPEM: []byte("public-chain"), SANs: []string{"login.example"}, NotBefore: nanoTime, NotAfter: nanoTime.Add(time.Hour)}, ExpiresAt: nanoTime}
	assertNoZeroFields(t, "", reflect.ValueOf(a))
	a.Revision = 0
	if e := c.TLSAssets().Put(ctx, a, 0); e != nil {
		t.Fatal(e)
	}
	asset, e := c.TLSAssets().Get(ctx, a.Key)
	if e != nil {
		t.Fatal(e)
	}
	if diff := cmp.Diff(a, asset); diff != "" {
		t.Fatalf("TLS round trip (-want +got):\n%s", diff)
	}
	h := &store.HostBinding{Host: "login.example", TenantID: "tenant", DomainID: "domain", Generation: 4, Kind: store.HostPublic, Active: true}
	assertNoZeroFields(t, "", reflect.ValueOf(h))
	if e := c.CustomDomains().PutHost(ctx, h); e != nil {
		t.Fatal(e)
	}
	host, e := c.CustomDomains().GetHost(ctx, h.Host)
	if e != nil {
		t.Fatal(e)
	}
	if diff := cmp.Diff(h, host); diff != "" {
		t.Fatalf("host round trip (-want +got):\n%s", diff)
	}
	l, e := c.TLSAssets().ClaimLease(ctx, "cert", "worker", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	assertNoZeroFields(t, "", reflect.ValueOf(l))
}

type unavailableDomainStore struct{ store.Store }

func (unavailableDomainStore) CustomDomains() store.CustomDomains {
	return store.UnimplementedCustomDomains{}
}

type unavailableTLSStore struct{ store.Store }

func (unavailableTLSStore) TLSAssets() store.TLSAssets { return store.UnimplementedTLSAssets{} }

// A new protocol wrapper over an old backing driver cannot advertise support
// solely because it recognizes the new protobuf messages.
func TestCustomDomainCapabilityChecksBacking(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(store.Store) store.Store
		want error
	}{
		{"registry", func(s store.Store) store.Store { return unavailableDomainStore{s} }, store.ErrCustomDomainRepositoryUnavailable},
		{"tls", func(s store.Store) store.Store { return unavailableTLSStore{s} }, store.ErrTLSAssetRepositoryUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, tc.wrap(memory.New()))
			defer c.Close()
			ctx := context.Background()
			if e := c.requireCustomDomains(ctx); !errors.Is(e, tc.want) {
				t.Fatalf("capability = %v, want %v", e, tc.want)
			}
			if e := c.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t", CanonicalHost: "canonical.example"}); !errors.Is(e, tc.want) {
				t.Fatalf("canonical write = %v, want %v", e, tc.want)
			}
			if _, e := c.Tenants().Get(ctx, "t"); !errors.Is(e, store.ErrNotFound) {
				t.Fatalf("capability refusal wrote tenant: %v", e)
			}
		})
	}
}

// All twenty new methods reject a missing RPC with the exact capability
// sentinel, including list/default calls that must never fake empty data.
func persistenceCalls(c *Client, ctx context.Context) map[string]func() error {
	d := c.CustomDomains()
	a := c.TLSAssets()
	row := &store.CustomDomain{TenantID: "t", ID: "d", Domain: "login.example"}
	asset := &store.TLSAsset{Key: "cert"}
	lease := store.TLSLease{Key: "cert", Owner: "worker", Fence: 1, Until: time.Now().Add(time.Minute)}
	return map[string]func() error{
		"domain-get":      func() error { _, e := d.Get(ctx, "t", "d"); return e },
		"domain-list":     func() error { _, e := d.List(ctx, "t"); return e },
		"domain-due":      func() error { _, e := d.ListDue(ctx, 1); return e },
		"domain-create":   func() error { return d.Create(ctx, row) },
		"domain-update":   func() error { return d.Update(ctx, row, 1) },
		"domain-delete":   func() error { return d.Delete(ctx, "t", "d", 1) },
		"domain-get-host": func() error { _, e := d.GetHost(ctx, "login.example"); return e },
		"domain-put-host": func() error {
			return d.PutHost(ctx, &store.HostBinding{Host: "login.example", TenantID: "t", DomainID: "d"})
		},
		"domain-delete-host": func() error { return d.DeleteHost(ctx, "login.example", "t", "d") },
		"domain-get-default": func() error { _, e := d.GetDefault(ctx, "t"); return e },
		"domain-set-default": func() error { return d.SetDefault(ctx, "t", "d") },
		"domain-admit":       func() error { _, e := d.AdmitAttempt(ctx, "t", "d"); return e },
		"tls-get":            func() error { _, e := a.Get(ctx, "cert"); return e },
		"tls-put":            func() error { return a.Put(ctx, asset, 0) },
		"tls-delete":         func() error { return a.Delete(ctx, "cert", 1) },
		"tls-expired":        func() error { _, e := a.ListExpired(ctx, 1); return e },
		"tls-claim":          func() error { _, e := a.ClaimLease(ctx, "cert", "worker", time.Minute); return e },
		"tls-renew":          func() error { _, e := a.RenewLease(ctx, lease, time.Minute); return e },
		"tls-check":          func() error { return a.CheckLease(ctx, lease) },
		"tls-release":        func() error { return a.ReleaseLease(ctx, lease) },
	}
}

func TestPersistenceOldPluginMethodsUnavailable(t *testing.T) {
	c := serveOldPlugin(t)
	defer c.Close()
	for name, call := range persistenceCalls(c, context.Background()) {
		t.Run(name, func(t *testing.T) {
			want := store.ErrCustomDomainRepositoryUnavailable
			if strings.HasPrefix(name, "tls-") {
				want = store.ErrTLSAssetRepositoryUnavailable
			}
			e := call()
			if !errors.Is(e, want) || status.Code(e) != codes.Unimplemented {
				t.Fatalf("missing method = %v, want %v plus Unimplemented", e, want)
			}
		})
	}
}

func TestPersistenceContextErrors(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	for _, kind := range []string{"canceled", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if kind == "canceled" {
				ctx, cancel = context.WithCancel(context.Background())
				cancel()
			} else {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				want = context.DeadlineExceeded
			}
			calls := persistenceCalls(c, ctx)
			calls["probe"] = func() error { return c.requireCustomDomains(ctx) }
			for name, call := range calls {
				t.Run(name, func(t *testing.T) {
					e := call()
					if !errors.Is(e, want) {
						t.Fatalf("context = %v, want %v", e, want)
					}
					assertTransportErr(t, e)
					if errors.Is(e, store.ErrCustomDomainRepositoryUnavailable) || errors.Is(e, store.ErrTLSAssetRepositoryUnavailable) {
						t.Fatalf("context became missing capability: %v", e)
					}
				})
			}
		})
	}
}

func TestOriginCapabilityProbeUsesNestedTransaction(t *testing.T) {
	for _, driver := range []struct {
		name string
		open func(*testing.T) *Client
	}{{"memory", inProcess}, {"sqlite", inProcessSQLite}} {
		t.Run(driver.name, func(t *testing.T) {
			c := driver.open(t)
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			e := c.WithTx(ctx, func(tx store.Store) error {
				return tx.WithTx(ctx, func(inner store.Store) error {
					if e := inner.Tenants().Create(ctx, &store.Tenant{ID: "nested", Name: "nested", CanonicalHost: "canonical.example"}); e != nil {
						return e
					}
					return inner.Sessions().Create(ctx, &store.LoginSession{TenantID: "nested", ID: "session", TokenHash: "hash", Origin: "https://login.example"})
				})
			})
			if e != nil {
				t.Fatal(e)
			}
			s, e := c.Sessions().Get(ctx, "nested", "session")
			if e != nil || s.Origin != "https://login.example" {
				t.Fatalf("nested origin = %+v, %v", s, e)
			}
		})
	}
}

type flakyCapabilityPlugin struct {
	*Server
	probes atomic.Int32
}

func (p *flakyCapabilityPlugin) CustomDomainsSupported(ctx context.Context, q *storev1.CustomDomainCapabilitiesRequest) (*storev1.Result, error) {
	if p.probes.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "temporary backend failure")
	}
	return p.Server.CustomDomainsSupported(ctx, q)
}
func TestCapabilityTransientFailureDoesNotWriteOrCacheSuccess(t *testing.T) {
	srv := NewServer(memory.New())
	defer srv.Close()
	c := serveWith(t, &flakyCapabilityPlugin{Server: srv})
	defer c.Close()
	ctx := context.Background()
	row := &store.Tenant{ID: "tenant", Name: "tenant", CanonicalHost: "canonical.example"}
	e := c.Tenants().Create(ctx, row)
	if status.Code(e) != codes.Unavailable || errors.Is(e, store.ErrCustomDomainRepositoryUnavailable) {
		t.Fatalf("temporary probe = %v", e)
	}
	if _, e := c.Tenants().Get(ctx, row.ID); !errors.Is(e, store.ErrNotFound) {
		t.Fatalf("failed probe wrote tenant: %v", e)
	}
	if e := c.Tenants().Create(ctx, row); e != nil {
		t.Fatalf("successful retry = %v", e)
	}
	got, e := c.Tenants().Get(ctx, row.ID)
	if e != nil || got.CanonicalHost != row.CanonicalHost {
		t.Fatalf("successful retry row = %+v, %v", got, e)
	}
}

func TestPrivatePersistenceCodecPresence(t *testing.T) {
	roundTrip(t, "zero-domain", &store.CustomDomain{}, customDomainToPB, customDomainFromPB)
	roundTrip(t, "empty-domain", &store.CustomDomain{DomainMetadata: map[string]string{}, ProofToken: []byte{}, ProxyKeyHash: []byte{}}, customDomainToPB, customDomainFromPB)
	roundTrip(t, "zero-asset", &store.TLSAsset{}, tlsAssetToPB, tlsAssetFromPB)
	roundTrip(t, "empty-asset", &store.TLSAsset{Ciphertext: []byte{}, PublicData: store.TLSPublicData{SANs: []string{}, CertificateChainPEM: []byte{}}}, tlsAssetToPB, tlsAssetFromPB)
	roundTrip(t, "zero-lease", &store.TLSLease{}, tlsLeaseToPB, tlsLeaseFromPB)
	roundTrip(t, "zero-host", &store.HostBinding{}, hostBindingToPB, hostBindingFromPB)
}

func TestPrivatePersistenceMalformedRequests(t *testing.T) {
	srv := NewServer(memory.New())
	defer srv.Close()
	ctx := context.Background()
	bad := &timestamppb.Timestamp{Seconds: 1 << 60}
	for name, call := range map[string]func() (*storev1.CustomDomainResult, error){
		"domain-missing": func() (*storev1.CustomDomainResult, error) {
			return srv.CustomDomainsCreate(ctx, &storev1.CustomDomainRequest{})
		},
		"domain-time": func() (*storev1.CustomDomainResult, error) {
			return srv.CustomDomainsUpdate(ctx, &storev1.CustomDomainRequest{Value: &storev1.CustomDomain{NextAttemptAt: bad}})
		},
		"host-missing": func() (*storev1.CustomDomainResult, error) {
			return srv.CustomDomainsPutHost(ctx, &storev1.CustomDomainRequest{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, e := call()
			if e != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
				t.Fatalf("malformed request = %v, %v", r, e)
			}
		})
	}
	for name, call := range map[string]func() (*storev1.TLSAssetResult, error){
		"asset-missing": func() (*storev1.TLSAssetResult, error) { return srv.TLSAssetsPut(ctx, &storev1.TLSAssetRequest{}) },
		"asset-time": func() (*storev1.TLSAssetResult, error) {
			return srv.TLSAssetsPut(ctx, &storev1.TLSAssetRequest{Value: &storev1.TLSAsset{PublicData: &storev1.TLSPublicData{NotAfter: bad}}})
		},
		"claim-duration-missing": func() (*storev1.TLSAssetResult, error) {
			return srv.TLSAssetsClaimLease(ctx, &storev1.TLSAssetRequest{})
		},
		"renew-lease-missing": func() (*storev1.TLSAssetResult, error) {
			return srv.TLSAssetsRenewLease(ctx, &storev1.TLSAssetRequest{Duration: durationpb.New(time.Minute)})
		},
		"check-lease-time": func() (*storev1.TLSAssetResult, error) {
			return srv.TLSAssetsCheckLease(ctx, &storev1.TLSAssetRequest{Lease: &storev1.TLSLease{Until: bad}})
		},
		"release-lease-missing": func() (*storev1.TLSAssetResult, error) {
			return srv.TLSAssetsReleaseLease(ctx, &storev1.TLSAssetRequest{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, e := call()
			if e != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
				t.Fatalf("malformed request = %v, %v", r, e)
			}
		})
	}
}
