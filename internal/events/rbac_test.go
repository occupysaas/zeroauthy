package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func roleDeletionFixture(t *testing.T) (context.Context, store.Store, string, string) {
	t.Helper()
	ctx, s := fixture(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	oid := "org_1234567890abcdef"
	rid := "rol_1234567890abcdef"
	for _, id := range []string{"active", "dormant", "global"} {
		must(s.Users().Create(ctx, user(id)))
	}
	must(s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
	must(s.Organizations().AddMembers(ctx, "ten", oid, []string{"active", "dormant"}))
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: rid, Name: "reader"}))
	for _, id := range []string{"active", "dormant"} {
		must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, id, true, []string{rid}))
	}
	must(s.Organizations().RemoveMembers(ctx, "ten", oid, []string{"dormant"}))
	must(s.RBAC().AssignRoleUsers(ctx, "ten", rid, []string{"global"}))
	return ctx, s, oid, rid
}

func TestDecoratorRoleDeleteCapturesOnlyActiveEdges(t *testing.T) {
	ctx, s, oid, rid := roleDeletionFixture(t)
	before := len(all(t, ctx, s))
	if err := s.RBAC().DeleteRole(ctx, "ten", rid); err != nil {
		t.Fatal(err)
	}
	es := all(t, ctx, s)[before:]
	if len(es) != 1 || es[0].Type != "organization.member.role.deleted" {
		t.Fatalf("role removal events=%v", es)
	}
	if err := eventrules.ValidateEvent(es[0].Body); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Data struct {
			Object struct {
				Organization struct {
					ID string `json:"id"`
				} `json:"organization"`
				User struct {
					ID string `json:"user_id"`
				} `json:"user"`
				Role struct{ ID, Name string } `json:"role"`
			} `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(es[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	obj := body.Data.Object
	if obj.Organization.ID != oid || obj.User.ID != "active" || obj.Role.ID != rid || obj.Role.Name != "reader" {
		t.Fatalf("incorrect deleted edge=%+v", obj)
	}
	roles, err := s.Organizations().MemberRoles(ctx, "ten", oid, "active", store.OrgPage{})
	if err != nil || len(roles.Items) != 0 {
		t.Fatalf("role assignment survived: %v %v", roles, err)
	}
	if _, err := s.RBAC().GetRole(ctx, "ten", rid); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.RBAC().DeleteRole(ctx, "ten", rid); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != before+1 {
		t.Fatal("missing role generated a removal event")
	}
}

func TestDecoratorRoleDeleteRollbackEmitsNothing(t *testing.T) {
	ctx, s, oid, rid := roleDeletionFixture(t)
	before := len(all(t, ctx, s))
	abort := errors.New("abort after role deletion")
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.RBAC().DeleteRole(ctx, "ten", rid); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != before {
		t.Fatal("rolled-back role deletion emitted events")
	}
	if _, err := s.RBAC().GetRole(ctx, "ten", rid); err != nil {
		t.Fatal(err)
	}
	roles, err := s.Organizations().MemberRoles(ctx, "ten", oid, "active", store.OrgPage{})
	if err != nil || len(roles.Items) != 1 || roles.Items[0] != rid {
		t.Fatalf("role rollback failed: %v %v", roles, err)
	}
}

func TestDecoratorRoleDeletePagesAndIsolatesTenants(t *testing.T) {
	ctx, s := fixture(t)
	rid := "rol_1234567890abcdef"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Users().Create(ctx, user("member")))
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: rid, Name: "reader"}))
	must(s.WithTx(ctx, func(tx store.Store) error {
		for i := range 105 {
			oid := fmt.Sprintf("org_%016d", i)
			if err := tx.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: fmt.Sprintf("org-%d", i)}, nil); err != nil {
				return err
			}
			if err := tx.Organizations().AddMembers(ctx, "ten", oid, []string{"member"}); err != nil {
				return err
			}
			if err := tx.Organizations().ChangeMemberRoles(ctx, "ten", oid, "member", true, []string{rid}); err != nil {
				return err
			}
		}
		return nil
	}))
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "other", Name: "other", CanonicalHost: "other.example"}))
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "other", ID: rid, Name: "reader"}))
	checkpoint, err := s.Events().LatestEventSeq(ctx, "ten")
	must(err)
	must(s.RBAC().DeleteRole(ctx, "ten", rid))
	count := 0
	for {
		page, err := s.Events().EventsAfter(ctx, "ten", checkpoint, nil, 100, time.Now().Add(time.Hour))
		must(err)
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if e.Type != "organization.member.role.deleted" {
				t.Fatalf("unexpected event %s", e.Type)
			}
			count++
			checkpoint = e.Seq
		}
	}
	if count != 105 {
		t.Fatalf("captured %d role edges, want105", count)
	}
	if _, err := s.RBAC().GetRole(ctx, "other", rid); err != nil {
		t.Fatalf("deleted another tenant's role: %v", err)
	}
}

func TestDecoratorRoleDeleteWithoutEventsSupport(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	rid := "rol_1234567890abcdef"
	if err := base.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: rid, Name: "reader"}); err != nil {
		t.Fatal(err)
	}
	s := events.Wrap(unavailableStore{base}, events.Config{})
	if err := s.RBAC().DeleteRole(ctx, "ten", rid); err != nil {
		t.Fatal(err)
	}
	es, err := base.Events().EventsAfter(ctx, "ten", 0, nil, 100, time.Now().Add(time.Hour))
	if err != nil || len(es) != 0 {
		t.Fatalf("unsupported capture=%v %v", es, err)
	}
}

func TestDecoratorRoleDeletePagesMembers(t *testing.T) {
	ctx, s := fixture(t)
	oid := "org_1234567890abcdef"
	rid := "rol_1234567890abcdef"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: rid, Name: "reader"}))
	must(s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
	must(s.WithTx(ctx, func(tx store.Store) error {
		ids := make([]string, 0, 105)
		for i := range 105 {
			uid := fmt.Sprintf("member-%03d", i)
			if err := tx.Users().Create(ctx, user(uid)); err != nil {
				return err
			}
			ids = append(ids, uid)
		}
		if err := tx.Organizations().AddMembers(ctx, "ten", oid, ids); err != nil {
			return err
		}
		for _, uid := range ids {
			if err := tx.Organizations().ChangeMemberRoles(ctx, "ten", oid, uid, true, []string{rid}); err != nil {
				return err
			}
		}
		return nil
	}))
	checkpoint, err := s.Events().LatestEventSeq(ctx, "ten")
	must(err)
	must(s.RBAC().DeleteRole(ctx, "ten", rid))
	count := 0
	for {
		page, err := s.Events().EventsAfter(ctx, "ten", checkpoint, nil, 100, time.Now().Add(time.Hour))
		must(err)
		if len(page) == 0 {
			break
		}
		for _, e := range page {
			if e.Type != "organization.member.role.deleted" {
				t.Fatal(e.Type)
			}
			count++
			checkpoint = e.Seq
		}
	}
	if count != 105 {
		t.Fatalf("captured%d members,want105", count)
	}
}

func TestDecoratorRoleDeleteOutboxFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	oid := "org_1234567890abcdef"
	rid := "rol_1234567890abcdef"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(base.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten", CanonicalHost: "ten.example"}))
	must(base.Users().Create(ctx, user("active")))
	must(base.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
	must(base.Organizations().AddMembers(ctx, "ten", oid, []string{"active"}))
	must(base.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: rid, Name: "reader"}))
	must(base.Organizations().ChangeMemberRoles(ctx, "ten", oid, "active", true, []string{rid}))
	s := events.Wrap(failingOutboxStore{base}, events.Config{})
	if err := s.RBAC().DeleteRole(ctx, "ten", rid); err == nil {
		t.Fatal("outbox failure swallowed")
	}
	if _, err := base.RBAC().GetRole(ctx, "ten", rid); err != nil {
		t.Fatal(err)
	}
	roles, err := base.Organizations().MemberRoles(ctx, "ten", oid, "active", store.OrgPage{})
	if err != nil || len(roles.Items) != 1 || roles.Items[0] != rid {
		t.Fatalf("outbox failure committed role removal: %v %v", roles, err)
	}
	if len(all(t, ctx, base)) != 0 {
		t.Fatal("failed append left events")
	}
}
