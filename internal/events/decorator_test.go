package events_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/eventrules"
	"github.com/zeroauthy/zeroauthy/internal/events"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func fixture(t *testing.T) (context.Context, store.Store) {
	t.Helper()
	ctx := context.Background()
	s := memory.New()
	if err := s.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten", CanonicalHost: "ten.example"}); err != nil {
		t.Fatal(err)
	}
	return ctx, events.Wrap(s, events.Config{})
}
func user(id string) *store.User {
	return &store.User{TenantID: "ten", UserID: id, Email: id + "@example.com"}
}
func all(t *testing.T, ctx context.Context, s store.Store) []store.TenantEvent {
	t.Helper()
	e, err := s.Events().EventsAfter(ctx, "ten", 0, nil, 100, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func TestDecoratorEmitsPerPath(t *testing.T) {
	ctx, s := fixture(t)
	u := user("u")
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	u.Name = "new"
	if err := s.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: "org_1234567890abcdef", Name: "org"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Organizations().AddMembers(ctx, "ten", "org_1234567890abcdef", []string{"u"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().Create(ctx, &store.Connection{TenantID: "ten", ID: "con_1234567890abcdef", Name: "oidc", Strategy: "oidc", Extra: map[string]any{"client_id": "example-client"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().Delete(ctx, "ten", "u"); err != nil {
		t.Fatal(err)
	}
	got := all(t, ctx, s)
	want := []string{"user.created", "user.updated", "organization.created", "organization.member.added", "connection.created", "organization.member.deleted", "user.deleted"}
	if len(got) != len(want) {
		t.Fatalf("events=%v", got)
	}
	for i, w := range want {
		if got[i].Type != w {
			t.Fatalf("type %d=%s", i, got[i].Type)
		}
	}
}
func TestDecoratorRollbackEmitsNothing(t *testing.T) {
	ctx, s := fixture(t)
	sentinel := errors.New("abort")
	err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, user("u")); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 0 {
		t.Fatal("rollback leaked event")
	}
	if _, err := s.Users().Get(ctx, "ten", "u"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}
func TestDecoratorCollapsesUpdates(t *testing.T) {
	ctx, s := fixture(t)
	u := user("u")
	u.Name = "original"
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		u.Name = "first"
		if err := tx.Users().Update(ctx, u); err != nil {
			return err
		}
		u.Name = "final"
		return tx.Users().Update(ctx, u)
	})
	if err != nil {
		t.Fatal(err)
	}
	es := all(t, ctx, s)
	if len(es) != 2 {
		t.Fatalf("count=%d", len(es))
	}
	var body map[string]any
	if err := json.Unmarshal(es[1].Body, &body); err != nil {
		t.Fatal(err)
	}
	d := body["data"].(map[string]any)
	if d["object"].(map[string]any)["name"] != "final" {
		t.Fatal(d)
	}
	prior := d["previous_object"].(map[string]any)
	if prior["name"] != "original" || prior["email"] != "u@example.com" || prior["user_id"] != "u" {
		t.Fatalf("full original prior lost: %v", prior)
	}
}
func TestDecoratorSkipsRecordLogin(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("u")); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().RecordLogin(ctx, "ten", "u", time.Now(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("login emitted event")
	}
}
func TestDecoratorSkipsNonCatalogStrategies(t *testing.T) {
	ctx, s := fixture(t)
	for _, strategy := range []string{"auth0", "google-oauth2"} {
		if err := s.Connections().Create(ctx, &store.Connection{TenantID: "ten", ID: strategy, Name: strategy, Strategy: strategy}); err != nil {
			t.Fatal(err)
		}
	}
	if len(all(t, ctx, s)) != 0 {
		t.Fatal("uncatalogued strategy emitted")
	}
}
func TestDecoratorAddsLittleLatency(t *testing.T) {
	run := func(wrap bool) time.Duration {
		s := memory.New()
		ctx, cancel := context.WithTimeout(context.Background(), captureLatencyGuard)
		defer cancel()
		_ = s.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten", CanonicalHost: "ten.example"})
		var st store.Store = s
		if wrap {
			st = events.Wrap(st, events.Config{})
		}
		start := time.Now()
		for i := range 1000 {
			if err := st.Users().Create(ctx, user(fmt.Sprint(i))); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start)
	}
	base := run(false)
	wrapped := run(true)
	t.Logf("1000 creates: base=%s captured=%s ratio=%.2f", base, wrapped, float64(wrapped)/float64(base))
	// The plan's 10% relative target was measured and not met; see Task3 ruling.
	if wrapped > captureLatencyGuard {
		t.Fatalf("1000 captures exceed regression guard: %s", wrapped)
	}
}

func TestDecoratorRollbackAfterUserUpdate(t *testing.T) {
	ctx, s := fixture(t)
	u := user("u")
	u.Name = "original"
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		u.Name = "rolled back"
		if err := tx.Users().Update(ctx, u); err != nil {
			return err
		}
		return tx.Users().Create(ctx, user("u"))
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("failed tx emitted")
	}
	stored, _ := s.Users().Get(ctx, "ten", "u")
	if stored.Name != "original" {
		t.Fatal(stored.Name)
	}
}
func TestDecoratorNestedRollback(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("u")); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		abort := errors.New("savepoint")
		err := tx.WithTx(ctx, func(nested store.Store) error {
			u, _ := nested.Users().Get(ctx, "ten", "u")
			u.Name = "rolled back"
			if err := nested.Users().Update(ctx, u); err != nil {
				return err
			}
			return abort
		})
		if !errors.Is(err, abort) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("savepoint leaked buffered event")
	}
}
func TestDecoratorPasswordAndImportedHash(t *testing.T) {
	ctx, s := fixture(t)
	u := user("u")
	u.Identities = []store.Identity{{Provider: "auth0", Connection: "db", UserID: "u", ImportedHash: "imported"}}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().UpgradeImportedHash(ctx, "ten", "u", "db", "imported", "upgraded", time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("hash upgrade emitted")
	}
	if err := s.Users().SetPasswordHash(ctx, "ten", "u", "db", "new", time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 2 {
		t.Fatal("password omitted")
	}
	if err := s.Users().SetPasswordHashIfEmpty(ctx, "ten", "u", "db", "other", time.Now()); !errors.Is(err, store.ErrConflict) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 2 {
		t.Fatal("failed password CAS emitted")
	}
}
func TestDecoratorMembershipResultAndNoops(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("u")); err != nil {
		t.Fatal(err)
	}
	oid := "org_1234567890abcdef"
	if err := s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil); err != nil {
		t.Fatal(err)
	}
	ids, err := store.AddMembersResult(ctx, s.Organizations(), "ten", oid, []string{"u", "u"})
	if err != nil || len(ids) != 1 {
		t.Fatalf("%v %v", ids, err)
	}
	ids, err = store.AddMembersResult(ctx, s.Organizations(), "ten", oid, []string{"u"})
	if err != nil || len(ids) != 0 {
		t.Fatalf("%v %v", ids, err)
	}
	if err := s.Organizations().RemoveMembers(ctx, "ten", oid, []string{"u", "u"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Organizations().RemoveMembers(ctx, "ten", oid, []string{"u"}); err != nil {
		t.Fatal(err)
	}
	es := all(t, ctx, s)
	if len(es) != 4 || es[3].Type != "organization.member.deleted" {
		t.Fatalf("%v", es)
	}
}

type unavailableStore struct{ store.Store }

func (unavailableStore) Events() store.Events                     { return store.UnimplementedEvents{} }
func (unavailableStore) CheckEventsSupport(context.Context) error { return store.ErrEventsUnavailable }
func (unavailableStore) EventsSupported() bool                    { return false }
func TestDecoratorUnsupportedPreservesOperations(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	s := events.Wrap(unavailableStore{base}, events.Config{})
	if s.(store.EventsSupporter).EventsSupported() {
		t.Fatal("unsupported exposed as supported")
	}
	if err := s.Users().Create(ctx, user("u")); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(ctx, func(tx store.Store) error { return tx.Users().Update(ctx, user("u")) }); err != nil {
		t.Fatal(err)
	}
	es, err := base.Events().EventsAfter(ctx, "ten", 0, nil, 100, time.Now().Add(time.Hour))
	if err != nil || len(es) != 0 {
		t.Fatalf("%v %v", es, err)
	}
}

type failingAppend struct{ store.Events }

func (failingAppend) AppendEvents(context.Context, []store.TenantEvent) error {
	return errors.New("outbox write failed")
}

type failingOutboxStore struct{ store.Store }

func (s failingOutboxStore) Events() store.Events { return failingAppend{s.Store.Events()} }
func (s failingOutboxStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	return s.Store.WithTx(ctx, func(tx store.Store) error { return fn(failingOutboxStore{tx}) })
}
func TestDecoratorOutboxFailureRollsBackBusinessWrite(t *testing.T) {
	ctx := context.Background()
	base := memory.New()
	if err := base.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "ten", CanonicalHost: "ten.example"}); err != nil {
		t.Fatal(err)
	}
	s := events.Wrap(failingOutboxStore{base}, events.Config{})
	if err := s.Users().Create(ctx, user("u")); err == nil {
		t.Fatal("append failure swallowed")
	}
	if _, err := base.Users().Get(ctx, "ten", "u"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if len(all(t, ctx, base)) != 0 {
		t.Fatal("partial outbox")
	}
}

func TestDecoratorNestedPanicRestoresBuffer(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("u")); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		func() {
			defer func() { _ = recover() }()
			_ = tx.WithTx(ctx, func(nested store.Store) error {
				u, _ := nested.Users().Get(ctx, "ten", "u")
				u.Name = "rolled back"
				if err := nested.Users().Update(ctx, u); err != nil {
					return err
				}
				panic("abort savepoint")
			})
		}()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 1 {
		t.Fatal("panic savepoint leaked buffered event")
	}
}
func TestDecoratorOrganizationAndConnectionPaths(t *testing.T) {
	ctx, s := fixture(t)
	oid := "org_1234567890abcdef"
	o := &store.Organization{TenantID: "ten", ID: oid, Name: "org"}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Users().Create(ctx, user("u")))
	c := &store.Connection{TenantID: "ten", ID: "con_1234567890abcdef", Name: "oidc", Strategy: "oidc", Extra: map[string]any{"client_id": "example-client"}}
	must(s.Connections().Create(ctx, c))
	c.Name = "updated"
	must(s.Connections().Update(ctx, c))
	must(s.Organizations().Create(ctx, o, nil))
	o.DisplayName = "changed"
	must(s.Organizations().Update(ctx, o))
	oc := store.OrganizationConnection{TenantID: "ten", OrganizationID: oid, ConnectionID: "con_1234567890abcdef", ShowAsButton: true}
	must(s.Organizations().PutConnection(ctx, oc, true))
	oc.ShowAsButton = false
	must(s.Organizations().PutConnection(ctx, oc, false))
	must(s.Organizations().DeleteConnection(ctx, "ten", oid, "con_1234567890abcdef"))
	must(s.Organizations().DeleteConnection(ctx, "ten", oid, "con_1234567890abcdef"))
	must(s.Organizations().AddMembers(ctx, "ten", oid, []string{"u"}))
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: "rol_1234567890abcdef", Name: "reader"}))
	must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", true, []string{"rol_1234567890abcdef"}))
	must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", true, []string{"rol_1234567890abcdef"}))
	must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", false, []string{"rol_1234567890abcdef"}))
	must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", false, []string{"rol_1234567890abcdef"}))
	must(s.Organizations().Delete(ctx, "ten", oid))
	must(s.Connections().Delete(ctx, "ten", "con_1234567890abcdef"))
	got := all(t, ctx, s)
	want := []string{"user.created", "connection.created", "connection.updated", "organization.created", "organization.updated", "organization.connection.added", "organization.connection.updated", "organization.connection.removed", "organization.member.added", "organization.member.role.assigned", "organization.member.role.deleted", "organization.member.deleted", "organization.deleted", "connection.deleted"}
	if len(got) != len(want) {
		t.Fatalf("count=%d want=%d", len(got), len(want))
	}
	for i, e := range got {
		if e.Type != want[i] {
			t.Fatalf("%d type=%s", i, e.Type)
		}
		if err := eventrules.ValidateEvent(e.Body); err != nil {
			t.Fatalf("invalid %s: %s: %v", e.Type, e.Body, err)
		}
	}
}

func TestDecoratorInitialOrganizationConnectionsUseStoredDefaults(t *testing.T) {
	ctx, s := fixture(t)
	c := &store.Connection{TenantID: "ten", ID: "con_1234567890abcdef", Name: "oidc", Strategy: "oidc", Extra: map[string]any{"client_id": "client"}}
	if err := s.Connections().Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	o := &store.Organization{TenantID: "ten", ID: "org_1234567890abcdef", Name: "org"}
	if err := s.Organizations().Create(ctx, o, []store.OrganizationConnection{{ConnectionID: c.ID, ShowAsButton: true}}); err != nil {
		t.Fatal(err)
	}
	stored, err := s.Organizations().GetConnection(ctx, "ten", o.ID, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	es := all(t, ctx, s)
	var body map[string]any
	_ = json.Unmarshal(es[len(es)-1].Body, &body)
	obj := body["data"].(map[string]any)["object"].(map[string]any)
	if obj["organization_access_level"] != stored.OrganizationAccessLevel || obj["organization_member_access_level"] != stored.OrganizationMemberAccessLevel {
		t.Fatalf("captured unnormalized state: %v; stored=%+v", obj, stored)
	}
}

type capabilityStore struct {
	store.Store
	sentinel error
}

func (s capabilityStore) CheckRBACSupport(context.Context) error             { return s.sentinel }
func (s capabilityStore) CheckActionsSupport(context.Context) error          { return s.sentinel }
func (s capabilityStore) CheckOrganizationsSupport(context.Context) error    { return s.sentinel }
func (s capabilityStore) OrganizationsSupported() bool                       { return false }
func (s capabilityStore) CheckOrganizationsIISupport(context.Context) error  { return s.sentinel }
func (s capabilityStore) OrganizationsIISupported() bool                     { return false }
func (s capabilityStore) CheckLogsSupport(context.Context) error             { return s.sentinel }
func (s capabilityStore) LogsSupported() bool                                { return false }
func (s capabilityStore) MicrosoftFederationSupported(context.Context) error { return s.sentinel }
func (s capabilityStore) CheckEventsSupport(context.Context) error           { return s.sentinel }
func (s capabilityStore) EventsSupported() bool                              { return false }
func TestDecoratorForwardsCapabilities(t *testing.T) {
	ctx := context.Background()
	sentinel := errors.New("capability failure")
	s := events.Wrap(capabilityStore{Store: memory.New(), sentinel: sentinel}, events.Config{})
	for name, probe := range map[string]func(context.Context) error{"rbac": s.(store.RBACSupporter).CheckRBACSupport, "actions": s.(store.ActionsSupporter).CheckActionsSupport, "organizations": s.(store.OrganizationsSupporter).CheckOrganizationsSupport, "organizationsII": s.(store.OrganizationsIISupporter).CheckOrganizationsIISupport, "logs": s.(store.LogsSupporter).CheckLogsSupport, "microsoft": s.(store.MicrosoftFederationSupporter).MicrosoftFederationSupported, "events": s.(store.EventsSupporter).CheckEventsSupport} {
		if err := probe(ctx); !errors.Is(err, sentinel) {
			t.Fatalf("%s lost error: %v", name, err)
		}
	}
	if s.(store.OrganizationsSupporter).OrganizationsSupported() || s.(store.OrganizationsIISupporter).OrganizationsIISupported() || s.(store.LogsSupporter).LogsSupported() || s.(store.EventsSupporter).EventsSupported() {
		t.Fatal("unsupported capability became supported")
	}
	if err := s.Users().Create(ctx, user("u")); !errors.Is(err, sentinel) {
		t.Fatalf("transient event capability error must prevent unrecorded mutation: %v", err)
	}
}

func TestDecoratorCapturesConnectionCascadeAndRollback(t *testing.T) {
	ctx, s := fixture(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	db := &store.Connection{TenantID: "ten", ID: "db", Name: "db", Strategy: "auth0"}
	must(s.Connections().Create(ctx, db))
	owned := user("auth0|owned")
	owned.Identities = []store.Identity{{Provider: "auth0", UserID: "owned", Connection: "db"}}
	must(s.Users().Create(ctx, owned))
	survivor := user("auth0|survivor")
	survivor.Identities = []store.Identity{{Provider: "auth0", UserID: "survivor", Connection: "other"}, {Provider: "auth0", UserID: "linked", Connection: "db", ProfileData: map[string]any{"email": "linked@example.com"}}}
	must(s.Users().Create(ctx, survivor))
	oid := "org_1234567890abcdef"
	must(s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
	must(s.Organizations().AddMembers(ctx, "ten", oid, []string{owned.UserID}))
	must(s.Organizations().PutConnection(ctx, store.OrganizationConnection{TenantID: "ten", OrganizationID: oid, ConnectionID: "db", ShowAsButton: true}, true))
	before := len(all(t, ctx, s))
	abort := errors.New("abort")
	if err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Connections().Delete(ctx, "ten", "db"); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != before {
		t.Fatal("rollback leaked cascade events")
	}
	must(s.Connections().Delete(ctx, "ten", "db"))
	es := all(t, ctx, s)[before:]
	counts := map[string]int{}
	for _, e := range es {
		counts[e.Type]++
	}
	if counts["user.deleted"] != 1 || counts["user.updated"] != 1 || counts["organization.member.deleted"] != 1 || counts["organization.connection.removed"] != 1 || counts["connection.deleted"] != 0 {
		t.Fatal(counts)
	}
	if err := s.Connections().Delete(ctx, "ten", "db"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != before+4 {
		t.Fatal("repeat emitted cascade")
	}
	u, err := s.Users().Get(ctx, "ten", survivor.UserID)
	if err != nil || len(u.Identities) != 1 {
		t.Fatalf("%v %v", u, err)
	}
}
func TestDecoratorCapturesUserAndOrganizationCascades(t *testing.T) {
	for _, resource := range []string{"user", "organization"} {
		t.Run(resource, func(t *testing.T) {
			ctx, s := fixture(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(s.Users().Create(ctx, user("u")))
			oid := "org_1234567890abcdef"
			must(s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
			must(s.Organizations().AddMembers(ctx, "ten", oid, []string{"u"}))
			must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: "rol_1234567890abcdef", Name: "reader"}))
			must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", true, []string{"rol_1234567890abcdef"}))
			before := len(all(t, ctx, s))
			if resource == "user" {
				must(s.Users().Delete(ctx, "ten", "u"))
			} else {
				must(s.Organizations().Delete(ctx, "ten", oid))
			}
			es := all(t, ctx, s)[before:]
			counts := map[string]int{}
			for _, e := range es {
				counts[e.Type]++
			}
			if counts["organization.member.deleted"] != 1 || counts["organization.member.role.deleted"] != 1 || counts[resource+".deleted"] != 1 {
				t.Fatal(counts)
			}
		})
	}
}

func TestDecoratorCascadePagingBeyond100(t *testing.T) {
	ctx, s := fixture(t)
	oid := "org_1234567890abcdef"
	if err := s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil); err != nil {
		t.Fatal(err)
	}
	err := s.WithTx(ctx, func(tx store.Store) error {
		ids := []string{}
		for i := range 105 {
			id := fmt.Sprintf("user-%03d", i)
			if err := tx.Users().Create(ctx, user(id)); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return tx.Organizations().AddMembers(ctx, "ten", oid, ids)
	})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := s.Events().LatestEventSeq(ctx, "ten")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Organizations().Delete(ctx, "ten", oid); err != nil {
		t.Fatal(err)
	}
	members, deleted := 0, 0
	for {
		es, err := s.Events().EventsAfter(ctx, "ten", checkpoint, nil, 100, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(es) == 0 {
			break
		}
		for _, e := range es {
			if e.Type == "organization.member.deleted" {
				members++
			}
			if e.Type == "organization.deleted" {
				deleted++
			}
			checkpoint = e.Seq
		}
	}
	if members != 105 || deleted != 1 {
		t.Fatalf("members=%d organizations=%d", members, deleted)
	}
}
func TestDecoratorMemberRemovalKeepsRoles(t *testing.T) {
	ctx, s := fixture(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	oid := "org_1234567890abcdef"
	must(s.Users().Create(ctx, user("u")))
	must(s.Organizations().Create(ctx, &store.Organization{TenantID: "ten", ID: oid, Name: "org"}, nil))
	must(s.Organizations().AddMembers(ctx, "ten", oid, []string{"u"}))
	must(s.RBAC().CreateRole(ctx, &store.Role{TenantID: "ten", ID: "rol_1234567890abcdef", Name: "reader"}))
	must(s.Organizations().ChangeMemberRoles(ctx, "ten", oid, "u", true, []string{"rol_1234567890abcdef"}))
	before := len(all(t, ctx, s))
	must(s.Organizations().RemoveMembers(ctx, "ten", oid, []string{"u"}))
	es := all(t, ctx, s)[before:]
	if len(es) != 1 || es[0].Type != "organization.member.deleted" {
		t.Fatal(es)
	}
	must(s.Organizations().AddMembers(ctx, "ten", oid, []string{"u"}))
	roles, err := s.Organizations().MemberRoles(ctx, "ten", oid, "u", store.OrgPage{})
	if err != nil || len(roles.Items) != 1 {
		t.Fatalf("%v %v", roles, err)
	}
}

func TestDecoratorFederationAndPasswordCASPaths(t *testing.T) {
	ctx, s := fixture(t)
	u := user("u")
	u.Identities = []store.Identity{{Provider: "auth0", Connection: "db", UserID: "u"}}
	if err := s.Users().Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := s.Users().SetPasswordHashIfEmpty(ctx, "ten", "u", "db", "secret-hash", time.Now()); err != nil {
		t.Fatal(err)
	}
	key := store.FederatedIdentityKey{TenantID: "ten", ConnectionID: "social", Subject: "subject"}
	if err := s.Federation().PutIdentity(ctx, key, "u"); err != nil {
		t.Fatal(err)
	}
	if err := s.Federation().DeleteIdentity(ctx, key, "u"); err != nil {
		t.Fatal(err)
	}
	es := all(t, ctx, s)
	if len(es) != 4 {
		t.Fatalf("events=%d", len(es))
	}
	for _, e := range es[1:] {
		if e.Type != "user.updated" {
			t.Fatal(e.Type)
		}
		if strings.Contains(string(e.Body), "secret-hash") {
			t.Fatal("hash leaked")
		}
	}
}

func TestDecoratorTenantDeletionDiscardsBufferedEvents(t *testing.T) {
	ctx, s := fixture(t)
	if err := s.Users().Create(ctx, user("existing")); err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Users().Create(ctx, user("new")); err != nil {
			return err
		}
		return tx.Tenants().Delete(ctx, "ten")
	}); err != nil {
		t.Fatal(err)
	}
	if len(all(t, ctx, s)) != 0 {
		t.Fatal("tenant deletion recreated buffered events")
	}
	if _, err := s.Tenants().Get(ctx, "ten"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal(err)
	}
}

type unadvertisedUnavailable struct{ store.Store }

func (unadvertisedUnavailable) Events() store.Events { return store.UnimplementedEvents{} }
func TestDecoratorUnavailableWithoutProbe(t *testing.T) {
	s := events.Wrap(unadvertisedUnavailable{memory.New()}, events.Config{})
	if s.(store.EventsSupporter).EventsSupported() {
		t.Fatal("unimplemented repository advertised support")
	}
	if err := s.(store.EventsSupporter).CheckEventsSupport(context.Background()); !errors.Is(err, store.ErrEventsUnavailable) {
		t.Fatal(err)
	}
}
