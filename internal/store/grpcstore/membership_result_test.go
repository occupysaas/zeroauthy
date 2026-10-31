package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"testing"
)

func TestMembershipWriteResult(t *testing.T) {
	for _, tc := range []struct {
		name string
		open func(*testing.T) *Client
	}{{"memory", inProcess}, {"sqlite", inProcessSQLite}} {
		t.Run(tc.name, func(t *testing.T) {
			storetest.MembershipWriteResult(t, func(t *testing.T) store.Store { return tc.open(t) })
		})
	}
}

// An older plugin ignores the additive request flag and returns no insertion IDs.
type oldMembershipPlugin struct{ *Server }

func (p oldMembershipPlugin) OrganizationsAddMembers(ctx context.Context, q *storev1.OrganizationsRequest) (*storev1.OrganizationsResponse, error) {
	q.ReportInserted = false
	return p.Server.OrganizationsAddMembers(ctx, q)
}
func TestMembershipWriteResultOldPlugin(t *testing.T) {
	client := serveWith(t, oldMembershipPlugin{NewServer(memory.New())})
	defer client.Close()
	ctx := context.Background()
	if err := client.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}); err != nil {
		t.Fatal(err)
	}
	if err := client.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u"}); err != nil {
		t.Fatal(err)
	}
	org := &store.Organization{TenantID: "t", ID: "org_0000000000000001", Name: "org"}
	if err := client.Organizations().Create(ctx, org, nil); err != nil {
		t.Fatal(err)
	}
	ids, err := store.AddMembersResult(ctx, client.Organizations(), "t", org.ID, []string{"auth0|u"})
	if err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	member, err := client.Organizations().IsMember(ctx, "t", org.ID, "auth0|u")
	if err != nil || !member {
		t.Fatal(member, err)
	}
}
