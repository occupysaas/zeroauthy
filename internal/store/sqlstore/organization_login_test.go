package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type orgPolicyReadBarrier struct {
	store.Store
	afterRead func()
}

func (s orgPolicyReadBarrier) Organizations() store.Organizations {
	return orgPolicyConnections{Organizations: s.Store.Organizations(), afterRead: s.afterRead}
}

type orgPolicyConnections struct {
	store.Organizations
	afterRead func()
}

func (s orgPolicyConnections) GetConnection(ctx context.Context, tid, oid, cid string) (*store.OrganizationConnection, error) {
	link, err := s.Organizations.GetConnection(ctx, tid, oid, cid)
	if err == nil {
		s.afterRead()
	}
	return link, err
}

// Pause after the real eligibility read, and synchronously attempt a policy
// mutation before insertion. Either the writer commits and enrollment must
// refuse it, or the read locks the writer out until enrollment commits. A
// context deadline observes actual SQL lock blocking, not a scheduling sleep.
func TestOrganizationMembershipSQLPolicyOrdering(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			for _, change := range []string{"auto-off", "disable"} {
				t.Run(change, func(t *testing.T) {
					s := mk(t)
					ctx := context.Background()
					must := func(err error) {
						t.Helper()
						if err != nil {
							t.Fatal(err)
						}
					}
					must(s.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "t"}))
					must(s.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|u", Email: "u@example.test"}))
					must(s.Connections().Create(ctx, &store.Connection{TenantID: "t", ID: "con", Name: "Database", Strategy: store.StrategyDatabase}))
					org := &store.Organization{TenantID: "t", ID: "org_0000000000000001", Name: "org", DisplayName: "Org"}
					link := store.OrganizationConnection{TenantID: "t", OrganizationID: org.ID, ConnectionID: "con", ShowAsButton: true, AssignMembershipOnLogin: true}
					must(s.Organizations().Create(ctx, org, []store.OrganizationConnection{link}))
					var writerErr error
					read := false
					mutate := func(ctx context.Context) error {
						if change == "disable" {
							return s.Organizations().DeleteConnection(ctx, "t", org.ID, "con")
						}
						link.AssignMembershipOnLogin = false
						return s.Organizations().PutConnection(ctx, link, false)
					}
					loginErr := s.WithTx(ctx, func(tx store.Store) error {
						bound := orgPolicyReadBarrier{Store: tx, afterRead: func() {
							read = true
							writerCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
							defer cancel()
							writerErr = mutate(writerCtx)
						}}
						return orglogin.EnsureMembership(ctx, bound, orglogin.Context{Org: org}, "auth0|u", "con")
					})
					if !read {
						t.Fatal("eligibility read did not run")
					}
					member, err := s.Organizations().IsMember(ctx, "t", org.ID, "auth0|u")
					must(err)
					if writerErr == nil {
						if !errors.Is(loginErr, orglogin.ErrNotMember) || member {
							t.Fatalf("policy committed before insertion but stale enrollment succeeded: login=%v member=%v", loginErr, member)
						}
					} else {
						if !errors.Is(writerErr, context.DeadlineExceeded) {
							t.Fatalf("policy writer error: %v", writerErr)
						}
						must(loginErr)
						if !member {
							t.Fatal("serialized enrollment lost membership")
						}
						must(mutate(ctx)) // The writer proceeds once the login transaction ends.
					}
				})
			}
		})
	}
}
