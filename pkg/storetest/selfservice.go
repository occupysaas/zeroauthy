package storetest

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testSelfService is Plan 37c Phase B (scim.v1 version 2): self-service
// profiles unique by name, custom text, hashed SSO tickets that are
// revocable and single use, connection profiles, and tenant isolation and
// cascades.
func testSelfService(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s := open(t, newStore)
	if !store.SelfServiceAvailable(s) {
		t.Fatal("store must support scim.v1 version 2")
	}
	ss := s.SelfService()
	for _, tid := range []string{"ss-a", "ss-b"} {
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
	}
	doc := func(v string) json.RawMessage { return json.RawMessage(`{"description":"` + v + `"}`) }
	equalJSON := func(t *testing.T, got, want json.RawMessage) {
		t.Helper()
		var a, b any
		if json.Unmarshal(got, &a) != nil || json.Unmarshal(want, &b) != nil {
			t.Fatalf("invalid JSON %s / %s", got, want)
		}
		mustEqual(t, a, b)
	}

	t.Run("profiles", func(t *testing.T) {
		p1 := &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_1", Name: "Partners", Doc: doc("one"), CreatedAt: ts(0), UpdatedAt: ts(0)}
		p2 := &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_2", Name: "Vendors", Doc: doc("two"), CreatedAt: ts(1 * time.Minute), UpdatedAt: ts(1 * time.Minute)}
		mustNoErr(t, ss.CreateProfile(ctx, p1))
		mustNoErr(t, ss.CreateProfile(ctx, p2))
		mustErrIs(t, ss.CreateProfile(ctx, p1), store.ErrConflict)
		mustErrIs(t, ss.CreateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_3", Name: "Partners", Doc: doc("x"), CreatedAt: ts(2 * time.Minute), UpdatedAt: ts(2 * time.Minute)}), store.ErrConflict)
		// Another tenant may reuse ID and name.
		mustNoErr(t, ss.CreateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-b", ID: "ssp_1", Name: "Partners", Doc: doc("b"), CreatedAt: ts(0), UpdatedAt: ts(0)}))
		got, err := ss.GetProfile(ctx, "ss-a", "ssp_1")
		mustNoErr(t, err)
		if got.Name != "Partners" || !got.CreatedAt.Equal(ts(0)) {
			t.Fatalf("got %+v", got)
		}
		equalJSON(t, got.Doc, doc("one"))
		_, err = ss.GetProfile(ctx, "ss-a", "ssp_9")
		mustErrIs(t, err, store.ErrNotFound)
		list, total, err := ss.ListProfiles(ctx, "ss-a", store.Page{Limit: 1})
		mustNoErr(t, err)
		if total != 2 || len(list) != 1 || list[0].ID != "ssp_1" {
			t.Fatalf("list %d %+v", total, list)
		}
		list, _, err = ss.ListProfiles(ctx, "ss-a", store.Page{Offset: 1, Limit: 1})
		mustNoErr(t, err)
		if len(list) != 1 || list[0].ID != "ssp_2" {
			t.Fatalf("page 2 %+v", list)
		}
		mustErrIs(t, ss.UpdateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_2", Name: "Partners", Doc: doc("two"), UpdatedAt: ts(5 * time.Minute)}), store.ErrConflict)
		mustNoErr(t, ss.UpdateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_2", Name: "Suppliers", Doc: doc("new"), UpdatedAt: ts(5 * time.Minute)}))
		got, err = ss.GetProfile(ctx, "ss-a", "ssp_2")
		mustNoErr(t, err)
		if got.Name != "Suppliers" || !got.UpdatedAt.Equal(ts(5*time.Minute)) || !got.CreatedAt.Equal(ts(1*time.Minute)) {
			t.Fatalf("updated %+v", got)
		}
		equalJSON(t, got.Doc, doc("new"))
		mustErrIs(t, ss.UpdateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_9", Name: "Z", Doc: doc("z")}), store.ErrNotFound)
	})

	t.Run("custom text", func(t *testing.T) {
		text, err := ss.GetCustomText(ctx, "ss-a", "ssp_1", "en", "get-started")
		mustNoErr(t, err)
		if text != nil {
			t.Fatalf("unset text %s", text)
		}
		mustNoErr(t, ss.SetCustomText(ctx, "ss-a", "ssp_1", "en", "get-started", json.RawMessage(`{"introduction":"Welcome"}`)))
		mustNoErr(t, ss.SetCustomText(ctx, "ss-a", "ssp_1", "en", "get-started", json.RawMessage(`{"introduction":"Hello"}`)))
		text, err = ss.GetCustomText(ctx, "ss-a", "ssp_1", "en", "get-started")
		mustNoErr(t, err)
		equalJSON(t, text, json.RawMessage(`{"introduction":"Hello"}`))
		text, err = ss.GetCustomText(ctx, "ss-b", "ssp_1", "en", "get-started")
		mustNoErr(t, err)
		if text != nil {
			t.Fatalf("text crossed tenants: %s", text)
		}
		mustErrIs(t, ss.SetCustomText(ctx, "ss-a", "ssp_9", "en", "get-started", json.RawMessage(`{}`)), store.ErrNotFound)
	})

	t.Run("tickets", func(t *testing.T) {
		tk := &store.SSOTicket{TenantID: "ss-a", ID: "tkt_1", ProfileID: "ssp_1", Hash: "h1", Doc: json.RawMessage(`{"connection_config":{"name":"acme"}}`), CreatedAt: ts(0), ExpiresAt: ts(100 * time.Minute)}
		mustNoErr(t, ss.CreateTicket(ctx, tk))
		mustErrIs(t, ss.CreateTicket(ctx, &store.SSOTicket{TenantID: "ss-a", ID: "tkt_x", ProfileID: "ssp_9", Hash: "hx", Doc: json.RawMessage(`{}`), CreatedAt: ts(0), ExpiresAt: ts(100 * time.Minute)}), store.ErrNotFound)
		mustErrIs(t, ss.CreateTicket(ctx, &store.SSOTicket{TenantID: "ss-a", ID: "tkt_2", ProfileID: "ssp_1", Hash: "h1", Doc: json.RawMessage(`{}`), CreatedAt: ts(0), ExpiresAt: ts(100 * time.Minute)}), store.ErrConflict)
		got, err := ss.GetTicketByHash(ctx, "ss-a", "h1")
		mustNoErr(t, err)
		if got.ID != "tkt_1" || got.ProfileID != "ssp_1" || got.RevokedAt != nil || got.UsedAt != nil || !got.ExpiresAt.Equal(ts(100*time.Minute)) {
			t.Fatalf("ticket %+v", got)
		}
		_, err = ss.GetTicketByHash(ctx, "ss-b", "h1")
		mustErrIs(t, err, store.ErrNotFound)
		// Expired tickets cannot be used.
		mustErrIs(t, ss.UseTicket(ctx, "ss-a", "tkt_1", ts(100*time.Minute)), store.ErrPrecondition)
		mustNoErr(t, ss.UseTicket(ctx, "ss-a", "tkt_1", ts(50*time.Minute)))
		mustErrIs(t, ss.UseTicket(ctx, "ss-a", "tkt_1", ts(51*time.Minute)), store.ErrPrecondition)
		got, _ = ss.GetTicketByHash(ctx, "ss-a", "h1")
		if got.UsedAt == nil || !got.UsedAt.Equal(ts(50*time.Minute)) {
			t.Fatalf("used %+v", got)
		}
		mustNoErr(t, ss.CreateTicket(ctx, &store.SSOTicket{TenantID: "ss-a", ID: "tkt_3", ProfileID: "ssp_1", Hash: "h3", Doc: json.RawMessage(`{}`), CreatedAt: ts(0), ExpiresAt: ts(100 * time.Minute)}))
		mustErrIs(t, ss.RevokeTicket(ctx, "ss-a", "ssp_2", "tkt_3", ts(10*time.Minute)), store.ErrNotFound)
		mustNoErr(t, ss.RevokeTicket(ctx, "ss-a", "ssp_1", "tkt_3", ts(10*time.Minute)))
		mustNoErr(t, ss.RevokeTicket(ctx, "ss-a", "ssp_1", "tkt_3", ts(20*time.Minute)))
		got, _ = ss.GetTicketByHash(ctx, "ss-a", "h3")
		if got.RevokedAt == nil || !got.RevokedAt.Equal(ts(10*time.Minute)) {
			t.Fatalf("revoked %+v", got)
		}
		mustErrIs(t, ss.UseTicket(ctx, "ss-a", "tkt_3", ts(11*time.Minute)), store.ErrPrecondition)
		mustErrIs(t, ss.RevokeTicket(ctx, "ss-a", "ssp_1", "tkt_9", ts(10*time.Minute)), store.ErrNotFound)
		// A ticket is bound to at most one connection.
		mustNoErr(t, ss.BindTicketConnection(ctx, "ss-a", "tkt_3", "con_x"))
		mustNoErr(t, ss.BindTicketConnection(ctx, "ss-a", "tkt_3", "con_x"))
		mustErrIs(t, ss.BindTicketConnection(ctx, "ss-a", "tkt_3", "con_y"), store.ErrPrecondition)
		mustErrIs(t, ss.BindTicketConnection(ctx, "ss-a", "tkt_9", "con_x"), store.ErrNotFound)
		got, _ = ss.GetTicketByHash(ctx, "ss-a", "h3")
		if got.ConnectionID != "con_x" {
			t.Fatalf("bound %+v", got)
		}
	})

	t.Run("connection profiles", func(t *testing.T) {
		c1 := &store.ConnectionProfile{TenantID: "ss-a", ID: "cop_1", Name: "Default", Doc: doc("c"), CreatedAt: ts(0), UpdatedAt: ts(0)}
		mustNoErr(t, ss.CreateConnectionProfile(ctx, c1))
		mustErrIs(t, ss.CreateConnectionProfile(ctx, &store.ConnectionProfile{TenantID: "ss-a", ID: "cop_2", Name: "Default", Doc: doc("d"), CreatedAt: ts(1 * time.Minute), UpdatedAt: ts(1 * time.Minute)}), store.ErrConflict)
		mustNoErr(t, ss.CreateConnectionProfile(ctx, &store.ConnectionProfile{TenantID: "ss-a", ID: "cop_2", Name: "Strict", Doc: doc("d"), CreatedAt: ts(1 * time.Minute), UpdatedAt: ts(1 * time.Minute)}))
		got, err := ss.GetConnectionProfile(ctx, "ss-a", "cop_1")
		mustNoErr(t, err)
		equalJSON(t, got.Doc, doc("c"))
		_, err = ss.GetConnectionProfile(ctx, "ss-b", "cop_1")
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, ss.UpdateConnectionProfile(ctx, &store.ConnectionProfile{TenantID: "ss-a", ID: "cop_1", Name: "Renamed", Doc: doc("e"), UpdatedAt: ts(3 * time.Minute)}))
		mustErrIs(t, ss.UpdateConnectionProfile(ctx, &store.ConnectionProfile{TenantID: "ss-a", ID: "cop_2", Name: "Renamed", Doc: doc("e"), UpdatedAt: ts(3 * time.Minute)}), store.ErrConflict)
		list, total, err := ss.ListConnectionProfiles(ctx, "ss-a", store.Page{})
		mustNoErr(t, err)
		if total != 2 || list[0].Name != "Renamed" || !list[0].CreatedAt.Equal(ts(0)) || list[1].ID != "cop_2" {
			t.Fatalf("list %+v", list)
		}
		mustNoErr(t, ss.DeleteConnectionProfile(ctx, "ss-a", "cop_2"))
		mustErrIs(t, ss.DeleteConnectionProfile(ctx, "ss-a", "cop_2"), store.ErrNotFound)
	})

	t.Run("profile delete cascades", func(t *testing.T) {
		mustNoErr(t, ss.DeleteProfile(ctx, "ss-a", "ssp_1"))
		mustErrIs(t, ss.DeleteProfile(ctx, "ss-a", "ssp_1"), store.ErrNotFound)
		_, err := ss.GetTicketByHash(ctx, "ss-a", "h3")
		mustErrIs(t, err, store.ErrNotFound)
		// A new profile with the same ID starts without the old text.
		mustNoErr(t, ss.CreateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_1", Name: "Again", Doc: doc("a"), CreatedAt: ts(9 * time.Minute), UpdatedAt: ts(9 * time.Minute)}))
		text, err := ss.GetCustomText(ctx, "ss-a", "ssp_1", "en", "get-started")
		mustNoErr(t, err)
		if text != nil {
			t.Fatalf("custom text survived its profile: %s", text)
		}
		// The other tenant's profile is untouched.
		_, err = ss.GetProfile(ctx, "ss-b", "ssp_1")
		mustNoErr(t, err)
	})

	t.Run("tenant delete", func(t *testing.T) {
		mustNoErr(t, ss.CreateTicket(ctx, &store.SSOTicket{TenantID: "ss-b", ID: "tkt_b", ProfileID: "ssp_1", Hash: "hb", Doc: json.RawMessage(`{}`), CreatedAt: ts(0), ExpiresAt: ts(100 * time.Minute)}))
		mustNoErr(t, ss.CreateConnectionProfile(ctx, &store.ConnectionProfile{TenantID: "ss-b", ID: "cop_b", Name: "B", Doc: doc("b"), CreatedAt: ts(0), UpdatedAt: ts(0)}))
		mustNoErr(t, s.Tenants().Delete(ctx, "ss-b"))
		mustNoErr(t, s.Tenants().Create(ctx, &store.Tenant{ID: "ss-b", Name: "ss-b"}))
		if _, n, err := ss.ListProfiles(ctx, "ss-b", store.Page{}); err != nil || n != 0 {
			t.Fatalf("profiles survived the tenant: %d %v", n, err)
		}
		if _, err := ss.GetTicketByHash(ctx, "ss-b", "hb"); err == nil {
			t.Fatal("ticket survived the tenant")
		}
		if _, n, err := ss.ListConnectionProfiles(ctx, "ss-b", store.Page{}); err != nil || n != 0 {
			t.Fatalf("connection profiles survived the tenant: %d %v", n, err)
		}
	})

	t.Run("in transaction", func(t *testing.T) {
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.SelfService().CreateProfile(ctx, &store.SelfServiceProfile{TenantID: "ss-a", ID: "ssp_tx", Name: "Tx", Doc: doc("t"), CreatedAt: ts(0), UpdatedAt: ts(0)}); err != nil {
				return err
			}
			return store.ErrInvalid
		})
		mustErrIs(t, err, store.ErrInvalid)
		_, err = ss.GetProfile(ctx, "ss-a", "ssp_tx")
		mustErrIs(t, err, store.ErrNotFound)
	})
}
