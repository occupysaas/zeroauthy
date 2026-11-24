package storetest

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testDirectorySync is Plan 37c Phase C (scim.v1 version 3): one directory
// provisioning configuration per connection, a sealed administrator grant,
// synchronization scheduling with leases across tenants, the group
// selection, and the connection and tenant cascades.
func testDirectorySync(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	if !store.DirectorySyncAvailable(s) {
		t.Fatal("store must support scim.v1 version 3")
	}
	ds := s.DirectorySync()
	for _, tid := range []string{"ds-a", "ds-b"} {
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tid, "con1", "workspace")))
		mustNoErr(t, s.Connections().Create(ctx, newConnection(tid, "con2", "workspace-2")))
	}
	doc := json.RawMessage(`{"synchronize_automatically":true}`)
	prov := func(tid, conn string) *store.DirectoryProvisioning {
		return &store.DirectoryProvisioning{TenantID: tid, ConnectionID: conn, Doc: doc, CreatedAt: ts(0), UpdatedAt: ts(0)}
	}

	t.Run("configurations", func(t *testing.T) {
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-a", "con2")))
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-a", "con1")))
		mustErrIs(t, ds.CreateProvisioning(ctx, prov("ds-a", "con1")), store.ErrConflict)
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-b", "con1")))
		got, err := ds.GetProvisioning(ctx, "ds-a", "con1")
		mustNoErr(t, err)
		if got.AdminGrant != nil || got.LastSyncAt != nil || got.NextSyncAt != nil || got.LeaseUntil != nil || got.SyncID != "" || !got.CreatedAt.Equal(ts(0)) {
			t.Fatalf("got %+v", got)
		}
		_, err = ds.GetProvisioning(ctx, "ds-a", "con9")
		mustErrIs(t, err, store.ErrNotFound)

		last, next := ts(2*time.Minute), ts(42*time.Minute)
		got.AdminGrant, got.UpdatedAt, got.CreatedAt = []byte{1, 2, 3}, ts(time.Minute), ts(time.Hour)
		got.LastSyncAt, got.LastSyncStatus, got.LastSyncError, got.SyncID, got.NextSyncAt = &last, "failed", "Directory API refused", "dsy_1", &next
		mustNoErr(t, ds.UpdateProvisioning(ctx, got))
		again, err := ds.GetProvisioning(ctx, "ds-a", "con1")
		mustNoErr(t, err)
		if !slices.Equal(again.AdminGrant, []byte{1, 2, 3}) || !again.CreatedAt.Equal(ts(0)) || !again.UpdatedAt.Equal(ts(time.Minute)) ||
			again.LastSyncAt == nil || !again.LastSyncAt.Equal(last) || again.LastSyncStatus != "failed" || again.LastSyncError != "Directory API refused" ||
			again.SyncID != "dsy_1" || again.NextSyncAt == nil || !again.NextSyncAt.Equal(next) {
			t.Fatalf("after update %+v", again)
		}
		// Clearing optional fields.
		again.AdminGrant, again.NextSyncAt, again.LastSyncAt = nil, nil, nil
		mustNoErr(t, ds.UpdateProvisioning(ctx, again))
		if c, _ := ds.GetProvisioning(ctx, "ds-a", "con1"); c.AdminGrant != nil || c.NextSyncAt != nil || c.LastSyncAt != nil {
			t.Fatalf("not cleared %+v", c)
		}
		mustErrIs(t, ds.UpdateProvisioning(ctx, prov("ds-a", "con9")), store.ErrNotFound)

		list, total, err := ds.ListProvisionings(ctx, "ds-a", store.Page{Limit: 1})
		mustNoErr(t, err)
		if total != 2 || len(list) != 1 || list[0].ConnectionID != "con1" {
			t.Fatalf("list %d %+v", total, list)
		}
		list, _, _ = ds.ListProvisionings(ctx, "ds-a", store.Page{Offset: 1, Limit: 5})
		if len(list) != 1 || list[0].ConnectionID != "con2" {
			t.Fatalf("second page %+v", list)
		}
		mustNoErr(t, ds.DeleteProvisioning(ctx, "ds-a", "con2"))
		mustErrIs(t, ds.DeleteProvisioning(ctx, "ds-a", "con2"), store.ErrNotFound)
		if _, n, _ := ds.ListProvisionings(ctx, "ds-b", store.Page{}); n != 1 {
			t.Fatalf("other tenant has %d", n)
		}
	})

	t.Run("claim due", func(t *testing.T) {
		now := ts(time.Hour)
		due, later := ts(50*time.Minute), ts(2*time.Hour)
		set := func(tid, conn string, next *time.Time) {
			p, err := ds.GetProvisioning(ctx, tid, conn)
			mustNoErr(t, err)
			p.NextSyncAt, p.LeaseUntil = next, nil
			mustNoErr(t, ds.UpdateProvisioning(ctx, p))
		}
		set("ds-a", "con1", &due)
		set("ds-b", "con1", &later)
		got, err := ds.ClaimDue(ctx, now, 10*time.Minute, 10)
		mustNoErr(t, err)
		if len(got) != 1 || got[0].TenantID != "ds-a" || got[0].LeaseUntil == nil || !got[0].LeaseUntil.Equal(ts(70*time.Minute)) {
			t.Fatalf("claimed %+v", got)
		}
		// Leased: not claimed again until the lease runs out.
		if again, _ := ds.ClaimDue(ctx, now.Add(time.Minute), 10*time.Minute, 10); len(again) != 0 {
			t.Fatalf("claimed a leased configuration: %+v", again)
		}
		if again, _ := ds.ClaimDue(ctx, ts(71*time.Minute), 10*time.Minute, 10); len(again) != 1 {
			t.Fatalf("expired lease not reclaimed: %+v", again)
		}
		// Both due: the limit holds, earliest first.
		set("ds-a", "con1", &due)
		set("ds-b", "con1", &now)
		got, _ = ds.ClaimDue(ctx, ts(3*time.Hour), time.Minute, 1)
		if len(got) != 1 || got[0].TenantID != "ds-a" {
			t.Fatalf("limit/order %+v", got)
		}
		if none, _ := ds.ClaimDue(ctx, ts(3*time.Hour), time.Minute, 0); len(none) != 0 {
			t.Fatalf("limit 0 claimed %+v", none)
		}
		set("ds-a", "con1", nil)
		set("ds-b", "con1", nil)
		if none, _ := ds.ClaimDue(ctx, ts(10*time.Hour), time.Minute, 10); len(none) != 0 {
			t.Fatalf("unscheduled claimed %+v", none)
		}
	})

	t.Run("groups", func(t *testing.T) {
		g := func(id, name string) store.SynchronizedGroup {
			return store.SynchronizedGroup{GroupID: id, Doc: json.RawMessage(`{"name":"` + name + `"}`)}
		}
		mustNoErr(t, ds.ReplaceGroups(ctx, "ds-a", "con1", []store.SynchronizedGroup{g("02b", "B"), g("01a", "A"), g("02b", "dup")}))
		got, err := ds.ListGroups(ctx, "ds-a", "con1")
		mustNoErr(t, err)
		if len(got) != 2 || got[0].GroupID != "01a" || got[1].GroupID != "02b" || string(got[1].Doc) != `{"name":"B"}` {
			t.Fatalf("groups %+v", got)
		}
		if other, _ := ds.ListGroups(ctx, "ds-b", "con1"); len(other) != 0 {
			t.Fatalf("other tenant sees %+v", other)
		}
		mustNoErr(t, ds.ReplaceGroups(ctx, "ds-a", "con1", nil))
		if got, _ := ds.ListGroups(ctx, "ds-a", "con1"); len(got) != 0 {
			t.Fatalf("after clear %+v", got)
		}
		mustErrIs(t, ds.ReplaceGroups(ctx, "ds-a", "con9", []store.SynchronizedGroup{g("x", "X")}), store.ErrNotFound)
		_, err = ds.ListGroups(ctx, "ds-a", "con9")
		mustErrIs(t, err, store.ErrNotFound)
		// Deleting the configuration deletes its groups.
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-a", "con2")))
		mustNoErr(t, ds.ReplaceGroups(ctx, "ds-a", "con2", []store.SynchronizedGroup{g("03c", "C")}))
		mustNoErr(t, ds.DeleteProvisioning(ctx, "ds-a", "con2"))
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-a", "con2")))
		if got, _ := ds.ListGroups(ctx, "ds-a", "con2"); len(got) != 0 {
			t.Fatalf("groups survived the configuration: %+v", got)
		}
	})

	t.Run("cascades", func(t *testing.T) {
		mustNoErr(t, ds.ReplaceGroups(ctx, "ds-a", "con1", []store.SynchronizedGroup{{GroupID: "g1", Doc: json.RawMessage(`{}`)}}))
		mustNoErr(t, s.Connections().Delete(ctx, "ds-a", "con1"))
		_, err := ds.GetProvisioning(ctx, "ds-a", "con1")
		mustErrIs(t, err, store.ErrNotFound)
		// A new connection reusing the ID starts clean.
		mustNoErr(t, s.Connections().Create(ctx, newConnection("ds-a", "con1", "workspace")))
		mustNoErr(t, ds.CreateProvisioning(ctx, prov("ds-a", "con1")))
		if got, _ := ds.ListGroups(ctx, "ds-a", "con1"); len(got) != 0 {
			t.Fatalf("groups survived the connection: %+v", got)
		}
		mustNoErr(t, s.Tenants().Delete(ctx, "ds-b"))
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ds-b", Name: "ds-b"}))
		if _, n, _ := ds.ListProvisionings(ctx, "ds-b", store.Page{}); n != 0 {
			t.Fatalf("configurations survived the tenant: %d", n)
		}
		if _, n, _ := ds.ListProvisionings(ctx, "ds-a", store.Page{}); n != 2 {
			t.Fatalf("tenant ds-a has %d", n)
		}
	})
}
