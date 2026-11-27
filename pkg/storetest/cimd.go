package storetest

import (
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// testExternalClients covers Plan 41b's client external metadata: a Client
// ID Metadata Document URL is unique within a tenant and finds its client.
func testExternalClients(t *testing.T, newStore Factory) {
	ctx := t.Context()
	s := open(t, newStore)
	const url = "https://app.example.test/client.json"
	fetched := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	a := newClient("ten_a", "tpc_cimdA")
	a.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: store.ExternalCreatedByAdmin,
		ClientID: url, Status: store.ExternalStatusAvailable, FetchedAt: fetched, ExpiresAt: fetched.Add(5 * time.Minute)}
	mustNoErr(t, s.Clients().Create(ctx, a))
	got, err := s.Clients().Get(ctx, "ten_a", a.ClientID)
	mustNoErr(t, err)
	mustEqual(t, got, a)
	got.External.Status = "mutated"
	again, err := s.Clients().Get(ctx, "ten_a", a.ClientID)
	mustNoErr(t, err)
	mustEqual(t, again, a)

	byURL := func(tenantID, u string) []string {
		t.Helper()
		cs, total, err := s.Clients().List(ctx, tenantID, store.ClientFilter{ExternalClientID: u}, store.Page{})
		mustNoErr(t, err)
		ids := []string{}
		for _, c := range cs {
			ids = append(ids, c.ClientID)
		}
		if total != len(ids) {
			t.Fatalf("total %d for %v", total, ids)
		}
		return ids
	}
	mustEqual(t, byURL("ten_a", url), []string{"tpc_cimdA"})
	mustEqual(t, byURL("ten_a", url+"x"), []string{})
	mustEqual(t, byURL("ten_b", url), []string{})

	// Another client in the tenant cannot take the URL; another tenant can,
	// and a DCR client without a URL is no conflict.
	b := newClient("ten_a", "tpc_cimdB")
	b.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: store.ExternalCreatedByClient, ClientID: url}
	mustErrIs(t, s.Clients().Create(ctx, b), store.ErrConflict)
	_, err = s.Clients().Get(ctx, "ten_a", "tpc_cimdB")
	mustErrIs(t, err, store.ErrNotFound)
	b.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataDCR, CreatedBy: store.ExternalCreatedByClient}
	mustNoErr(t, s.Clients().Create(ctx, b))
	got, err = s.Clients().Get(ctx, "ten_a", "tpc_cimdB")
	mustNoErr(t, err)
	mustEqual(t, got, b)
	b.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: store.ExternalCreatedByClient, ClientID: url}
	mustErrIs(t, s.Clients().Update(ctx, b), store.ErrConflict)
	other := newClient("ten_b", "tpc_cimdA")
	other.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: store.ExternalCreatedByAdmin, ClientID: url}
	mustNoErr(t, s.Clients().Create(ctx, other))

	// An update that keeps the URL is no conflict; deleting frees it.
	a.External.Status = store.ExternalStatusUnavailable
	mustNoErr(t, s.Clients().Update(ctx, a))
	got, err = s.Clients().Get(ctx, "ten_a", a.ClientID)
	mustNoErr(t, err)
	mustEqual(t, got, a)
	mustNoErr(t, s.Clients().Delete(ctx, "ten_a", a.ClientID))
	mustEqual(t, byURL("ten_a", url), []string{})
	b.External = &store.ClientExternalMetadata{Type: store.ExternalMetadataCIMD, CreatedBy: store.ExternalCreatedByClient, ClientID: url}
	mustNoErr(t, s.Clients().Update(ctx, b))
	mustEqual(t, byURL("ten_a", url), []string{"tpc_cimdB"})

	// Clearing the metadata round trips as nil and frees the URL.
	b.External = nil
	mustNoErr(t, s.Clients().Update(ctx, b))
	got, err = s.Clients().Get(ctx, "ten_a", "tpc_cimdB")
	mustNoErr(t, err)
	mustEqual(t, got, b)
	mustEqual(t, byURL("ten_a", url), []string{})
}

// testDefaultClientGrants covers Plan 41b's default grants: no client, one
// per API and subject type, found with an empty client ID and by filter.
func testDefaultClientGrants(t *testing.T, newStore Factory) {
	ctx := t.Context()
	s := open(t, newStore)
	const aud = "https://api.example.test/"
	d := newClientGrant("ten_a", "cgr_default000000001", "", aud)
	d.DefaultFor = store.GrantDefaultForThirdParty
	d.SubjectType = store.SubjectTypeUser
	mustNoErr(t, s.ClientGrants().Create(ctx, d))
	got, err := s.ClientGrants().Find(ctx, "ten_a", "", aud, store.SubjectTypeUser)
	mustNoErr(t, err)
	mustEqual(t, got, d)
	_, err = s.ClientGrants().Find(ctx, "ten_a", "", aud, store.SubjectTypeClient)
	mustErrIs(t, err, store.ErrNotFound)

	dup := newClientGrant("ten_a", "cgr_default000000002", "", aud)
	dup.DefaultFor, dup.SubjectType = store.GrantDefaultForThirdParty, store.SubjectTypeUser
	mustErrIs(t, s.ClientGrants().Create(ctx, dup), store.ErrConflict)

	own := newClientGrant("ten_a", "cgr_own0000000000001", "app", aud)
	own.SubjectType = store.SubjectTypeUser
	mustNoErr(t, s.ClientGrants().Create(ctx, own))
	list, total, err := s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{DefaultFor: store.GrantDefaultForThirdParty}, store.Page{})
	mustNoErr(t, err)
	if total != 1 || len(list) != 1 || list[0].ID != d.ID {
		t.Fatalf("default_for filter = %d %+v", total, list)
	}
	list, total, err = s.ClientGrants().List(ctx, "ten_a", store.ClientGrantFilter{Audience: aud}, store.Page{})
	mustNoErr(t, err)
	if total != 2 || len(list) != 2 {
		t.Fatalf("audience filter = %d %+v", total, list)
	}

	// Updating scopes keeps it a default grant.
	d.Scopes = []string{"write:things"}
	mustNoErr(t, s.ClientGrants().Update(ctx, d))
	got, err = s.ClientGrants().Find(ctx, "ten_a", "", aud, store.SubjectTypeUser)
	mustNoErr(t, err)
	mustEqual(t, got, d)
	mustNoErr(t, s.ClientGrants().Delete(ctx, "ten_a", d.ID))
	_, err = s.ClientGrants().Find(ctx, "ten_a", "", aud, store.SubjectTypeUser)
	mustErrIs(t, err, store.ErrNotFound)
}
