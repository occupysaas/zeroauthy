package grpcstore

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Exercise the common repository contract through the plugin protocol.
func TestOrganizationsII(t *testing.T) {
	storetest.RunSuites(t, func(t *testing.T) store.Store { return serve(t, memory.New()) }, "OrganizationsII")
}

// iiCapabilityPlugin simulates version negotiation independently of Plan 29.
type iiCapabilityPlugin struct {
	*Server
	version   atomic.Int32
	transient atomic.Bool
	missing   bool
}

func (p *iiCapabilityPlugin) OrganizationsIICapabilities(context.Context, *storev1.PingRequest) (*storev1.OrganizationsCapabilitiesResult, error) {
	if p.missing {
		return nil, status.Error(codes.Unimplemented, "old plugin")
	}
	if p.transient.Swap(false) {
		return nil, status.Error(codes.Unavailable, "retry")
	}
	return &storev1.OrganizationsCapabilitiesResult{Version: uint32(p.version.Load())}, nil
}

type noIIBackend struct{ store.Store }

func (noIIBackend) OrganizationsII() store.OrganizationsII {
	return store.UnimplementedOrganizationsII{}
}

func TestOrganizationsIICapabilities(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		version int32
		missing bool
		want    bool
	}{{"v0", 0, false, false}, {"org-v1-only", 0, true, false}, {"II-v1", 1, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			m := memory.New()
			p := &iiCapabilityPlugin{Server: NewServer(m), missing: tc.missing}
			p.version.Store(tc.version)
			defer p.Close()
			c := serveWith(t, p)
			orgSeed(t, c)
			org := &store.Organization{TenantID: "t", ID: "org_abcdefghijklmnop", Name: "org"}
			if err := c.Organizations().Create(ctx, org, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Organizations().Get(ctx, "t", "org_abcdefghijklmnop"); err != nil {
				t.Fatal("v1 read", err)
			}
			if err := c.Clients().Create(ctx, &store.Client{TenantID: "t", ClientID: "client", Name: "client"}); err != nil {
				t.Fatal(err)
			}
			if got := c.OrganizationsIISupported(); got != tc.want {
				t.Fatalf("support %v", got)
			}
			err := c.OrganizationsII().PutClients(ctx, "t", "org_abcdefghijklmnop", []store.OrganizationClient{{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ClientID: "client"}})
			if tc.want {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
				t.Fatalf("mutation %v", err)
			}
			if err := c.WithTx(ctx, func(tx store.Store) error {
				capable := tx.(store.OrganizationsIISupporter)
				if capable.OrganizationsIISupported() != tc.want {
					return errors.New("transaction capability differs")
				}
				e := tx.OrganizationsII().PutClients(ctx, "t", "org_abcdefghijklmnop", []store.OrganizationClient{{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ClientID: "client"}})
				if tc.want {
					return e
				}
				if !errors.Is(e, store.ErrOrganizationsIIUnavailable) {
					return fmt.Errorf("transaction error %v", e)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			org.IsAppEntitlementActive = true
			err = c.Organizations().Update(ctx, org)
			if tc.want {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
				t.Fatalf("active entitlement silently discarded: %v", err)
			}
			conn := store.OrganizationConnection{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ConnectionID: "missing", IsEnabledSet: true, IsEnabled: false}
			err = c.Organizations().PutConnection(ctx, conn, true)
			if !tc.want && !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
				t.Fatalf("disabled connection silently discarded: %v", err)
			}
			grant := &store.ClientGrant{TenantID: "t", ID: "g", ClientID: "c", Audience: "api", OrganizationUsage: "require", AllowAnyOrganization: true}
			for _, write := range []func(context.Context, *store.ClientGrant) error{c.ClientGrants().Create, c.ClientGrants().Update} {
				err = write(ctx, grant)
				if !tc.want && !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
					t.Fatalf("grant policy silently discarded: %v", err)
				}
			}
			err = c.PasswordResetTickets().Create(ctx, &store.PasswordResetTicket{TenantID: "t", ID: "reset", OrganizationID: "org_abcdefghijklmnop"})
			if !tc.want && !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
				t.Fatalf("reset context silently discarded: %v", err)
			}
			if tc.want {
				if err != nil {
					t.Fatal(err)
				}
				got, e := c.PasswordResetTickets().GetByTokenHash(ctx, "t", "")
				if e != nil || got.OrganizationID != "org_abcdefghijklmnop" {
					t.Fatalf("reset organization roundtrip %v", e)
				}
			}
		})
	}
	t.Run("transient-recovery-reconnect", func(t *testing.T) {
		p := &iiCapabilityPlugin{Server: NewServer(memory.New())}
		p.version.Store(1)
		p.transient.Store(true)
		defer p.Close()
		c := serveWith(t, p)
		if c.OrganizationsIISupported() {
			t.Fatal("transient accepted")
		}
		if c.orgIICap.v.Load() != 0 {
			t.Fatal("transient cached")
		}
		if !c.OrganizationsIISupported() {
			t.Fatal("recovery not retried")
		}
		// Same connection/client after a server capability change: cached success
		// cannot authorize a write that the replacement server would discard.
		p.version.Store(0)
		if err := c.Organizations().Update(ctx, &store.Organization{IsAppEntitlementActive: true}); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			t.Fatalf("downgrade %v", err)
		}
		p.version.Store(1)
		if err := c.CheckOrganizationsIISupport(ctx); err != nil {
			t.Fatal(err)
		}
		if !c.OrganizationsIISupported() {
			t.Fatal("upgrade not recognized")
		}
	})
	t.Run("new-protocol-unavailable-backend", func(t *testing.T) {
		c := serve(t, noIIBackend{memory.New()})
		defer c.Close()
		if c.OrganizationsIISupported() {
			t.Fatal("unavailable backing store advertised")
		}
		if err := c.OrganizationsII().PutClients(ctx, "t", "org_abcdefghijklmnop", []store.OrganizationClient{{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ClientID: "client"}}); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			t.Fatal(err)
		}
	})
	t.Run("no-rpcs", func(t *testing.T) {
		c := serveWith(t, storev1.UnimplementedStoreServiceServer{})
		if c.OrganizationsIISupported() {
			t.Fatal("v0 supported")
		}
		if err := c.OrganizationsII().PutClients(ctx, "t", "org_abcdefghijklmnop", []store.OrganizationClient{{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ClientID: "client"}}); !errors.Is(err, store.ErrOrganizationsIIUnavailable) {
			t.Fatal(err)
		}
	})
}

func TestOrganizationsIIPluginRollback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		factory storetest.Factory
	}{{"memory", func(t *testing.T) store.Store { return serve(t, memory.New()) }}, {"sqlite", func(t *testing.T) store.Store { return inProcessSQLite(t) }}} {
		t.Run(tc.name, func(t *testing.T) { storetest.RunSuites(t, tc.factory, "OrganizationsII") })
	}
}

func TestOrganizationsIIPluginCodecs(t *testing.T) {
	now := time.Date(2026, 10, 29, 14, 15, 16, 123456789, time.UTC)
	for _, metadata := range []map[string]any{nil, {}, {"nested": map[string]any{"ok": true}}} {
		in := &store.OrganizationInvitation{TenantID: "t", OrganizationID: "org_abcdefghijklmnop", ID: "i", ClientID: "c", Roles: []string{}, UserMetadata: metadata, AppMetadata: metadata, WrappedTicket: []byte{0, 255, 3, 0}, TicketHash: "hash", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
		pb, err := organizationInvitationToPB(in)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := proto.Marshal(pb)
		if err != nil {
			t.Fatal(err)
		}
		pb = &storev1.OrganizationInvitationMsg{}
		if err = proto.Unmarshal(wire, pb); err != nil {
			t.Fatal(err)
		}
		out, err := organizationInvitationFromPB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("roundtrip mismatch: metadata nil=%v", metadata == nil)
		}
		out.WrappedTicket[0] = 99
		if in.WrappedTicket[0] != 0 {
			t.Fatal("byte alias")
		}
	}
	org := &store.Organization{TenantID: "t", ID: "org_abcdefghijklmnop", IsAppEntitlementActive: true}
	if out := orgFromPB(orgToPB(org)); !reflect.DeepEqual(org, out) {
		t.Fatal("entitlement codec")
	}
	in := store.OrganizationConnection{TenantID: "t", IsEnabledSet: true, IsEnabled: false, ConnectionName: "custom", OrganizationAccessLevel: "all", OrganizationMemberAccessLevel: "full"}
	if out := orgConnReadFromPB(orgConnToPB(in)); !reflect.DeepEqual(in, out) {
		t.Fatalf("disabled connection %+v", out)
	}
	omitted := orgConnFromPB(orgConnToPB(store.OrganizationConnection{}))
	if omitted.IsEnabledSet {
		t.Fatal("omission lost on write")
	}
	legacy := orgConnReadFromPB(&storev1.OrganizationConnectionMsg{})
	if !legacy.IsEnabled || !legacy.IsEnabledSet || legacy.OrganizationAccessLevel != "none" || legacy.OrganizationMemberAccessLevel != "limited" {
		t.Fatalf("legacy defaults %+v", legacy)
	}
	g := &store.ClientGrant{OrganizationUsage: "require", AllowAnyOrganization: true, SubjectType: store.SubjectTypeClient, CreatedAt: now}
	pb, _ := clientGrantToPB(g)
	got, err := clientGrantFromPB(pb)
	if err != nil || !reflect.DeepEqual(g, got) {
		t.Fatalf("grant codec %v", err)
	}
	reset := &store.PasswordResetTicket{TenantID: "t", OrganizationID: "org", CreatedAt: now, ExpiresAt: now}
	rp, _ := passwordResetTicketToPB(reset)
	ro, err := passwordResetTicketFromPB(rp)
	if err != nil || !reflect.DeepEqual(reset, ro) {
		t.Fatalf("reset codec %v", err)
	}
	if !errors.Is(errFromPB(errToPB(store.ErrOrganizationsIIUnavailable)), store.ErrOrganizationsIIUnavailable) {
		t.Fatal("unavailable error lost")
	}
}
