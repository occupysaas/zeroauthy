package storetest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func newTenant(name string) *store.Tenant {
	return &store.Tenant{
		ID:                  "ten_" + name,
		Name:                name,
		FriendlyName:        strings.ToUpper(name),
		Domains:             []string{name + ".example.test"},
		DefaultAudience:     "https://" + name + ".api.test",
		DefaultDirectory:    "Database",
		AllowedLogoutURLs:   []string{"https://" + name + ".example.test/bye"},
		EnabledLocales:      []string{"en", "fr"},
		CustomText:          store.CustomText{"login": {"fr": {"login": {"title": "Connexion"}}}},
		SessionLifetime:     3600,
		IdleSessionLifetime: 600,
		Branding:            store.Branding{LogoURL: "https://cdn.test/" + name + ".png", PrimaryColor: "#112233"},
		CreatedAt:           ts(0),
	}
}

func testTenants(t *testing.T, newStore Factory) {
	ctx := context.Background()

	t.Run("ConcurrentCreateDistinct", func(t *testing.T) {
		s := open(t, newStore)
		for i, err := range parallel(16, func(i int) error {
			return s.Tenants().Create(ctx, newTenant(fmt.Sprint("t", i)))
		}) {
			if err != nil {
				t.Errorf("create %d: %v", i, err)
			}
		}
	})

	t.Run("ConsentFlags", func(t *testing.T) {
		s := open(t, newStore)
		want := newTenant("acme")
		want.SkipNonVerifiableCallbackURIConfirmationPrompt = true
		want.UseScopeDescriptionsForConsent = true
		mustNoErr(t, s.Tenants().Create(ctx, want))
		got, err := s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		want.SkipNonVerifiableCallbackURIConfirmationPrompt = false
		want.UseScopeDescriptionsForConsent = false
		mustNoErr(t, s.Tenants().Update(ctx, want))
		got, err = s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})

	t.Run("CustomTextIsCopied", func(t *testing.T) {
		s := open(t, newStore)
		in := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, in))
		in.CustomText["login"]["fr"]["login"]["title"] = "mutated"
		in.EnabledLocales[0] = "xx"
		got, err := s.Tenants().Get(ctx, in.ID)
		mustNoErr(t, err)
		got.CustomText["login"]["fr"]["login"]["title"] = "mutated-too"
		again, _ := s.Tenants().Get(ctx, in.ID)
		mustEqual(t, again.CustomText["login"]["fr"]["login"]["title"], "Connexion")
		mustEqual(t, again.EnabledLocales, []string{"en", "fr"})
	})

	t.Run("CreateAndGet", func(t *testing.T) {
		s := open(t, newStore)
		want := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, want))

		got, err := s.Tenants().Get(ctx, want.ID)
		mustNoErr(t, err)
		mustEqual(t, got, want)

		got, err = s.Tenants().GetByName(ctx, "acme")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		got, err = s.Tenants().GetByDomain(ctx, "acme.example.test")
		mustNoErr(t, err)
		mustEqual(t, got, want)
	})

	t.Run("NotFound", func(t *testing.T) {
		s := open(t, newStore)
		_, err := s.Tenants().Get(ctx, "missing")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByName(ctx, "missing")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Tenants().GetByDomain(ctx, "missing.example.test")
		mustErrIs(t, err, store.ErrNotFound)
		mustErrIs(t, s.Tenants().Update(ctx, newTenant("missing")), store.ErrNotFound)
	})

	t.Run("Conflicts", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))

		sameID := newTenant("other")
		sameID.ID = "ten_acme"
		mustErrIs(t, s.Tenants().Create(ctx, sameID), store.ErrConflict)

		sameName := newTenant("acme")
		sameName.ID = "ten_x"
		sameName.Domains = []string{"x.example.test"}
		mustErrIs(t, s.Tenants().Create(ctx, sameName), store.ErrConflict)

		sameDomain := newTenant("other")
		sameDomain.Domains = []string{"other.example.test", "acme.example.test"}
		mustErrIs(t, s.Tenants().Create(ctx, sameDomain), store.ErrConflict)
	})

	t.Run("RepeatedDomainConflicts", func(t *testing.T) {
		s := open(t, newStore)
		dup := newTenant("acme")
		dup.Domains = []string{"acme.example.test", "login.acme.test", "acme.example.test"}
		mustErrIs(t, s.Tenants().Create(ctx, dup), store.ErrConflict)
		_, err := s.Tenants().Get(ctx, "ten_acme")
		mustErrIs(t, err, store.ErrNotFound)

		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		upd := newTenant("acme")
		upd.FriendlyName = "changed"
		upd.Domains = []string{"login.acme.test", "login.acme.test"}
		mustErrIs(t, s.Tenants().Update(ctx, upd), store.ErrConflict)
		got, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		mustEqual(t, got, newTenant("acme")) // nothing changed
	})

	t.Run("Update", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("globex")))

		upd := newTenant("acme")
		upd.FriendlyName = "Acme Corp"
		upd.Domains = []string{"acme.example.test", "login.acme.test"}
		mustNoErr(t, s.Tenants().Update(ctx, upd))
		got, err := s.Tenants().GetByDomain(ctx, "login.acme.test")
		mustNoErr(t, err)
		mustEqual(t, got, upd)

		steal := newTenant("acme")
		steal.Domains = []string{"globex.example.test"}
		mustErrIs(t, s.Tenants().Update(ctx, steal), store.ErrConflict)
	})

	t.Run("ListOrderedByName", func(t *testing.T) {
		s := open(t, newStore)
		for _, n := range []string{"zeta", "acme", "mid"} {
			mustNoErr(t, s.Tenants().Create(ctx, newTenant(n)))
		}
		got, err := s.Tenants().List(ctx)
		mustNoErr(t, err)
		var names []string
		for _, tn := range got {
			names = append(names, tn.Name)
		}
		mustEqual(t, names, []string{"acme", "mid", "zeta"})
	})

	t.Run("UpdateConflictsAndStaleDomains", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("acme")))
		mustNoErr(t, s.Tenants().Create(ctx, newTenant("globex")))
		rename := newTenant("acme")
		rename.Name = "globex"
		mustErrIs(t, s.Tenants().Update(ctx, rename), store.ErrConflict)
		missing := newTenant("nobody")
		mustErrIs(t, s.Tenants().Update(ctx, missing), store.ErrNotFound)

		moved := newTenant("acme")
		moved.Domains = []string{"login.acme.test"}
		mustNoErr(t, s.Tenants().Update(ctx, moved))
		_, err := s.Tenants().GetByDomain(ctx, "acme.example.test")
		mustErrIs(t, err, store.ErrNotFound) // the dropped domain is released
		claim := newTenant("globex")
		claim.Domains = []string{"globex.example.test", "acme.example.test"}
		mustNoErr(t, s.Tenants().Update(ctx, claim))
	})

	t.Run("ReturnsCopies", func(t *testing.T) {
		s := open(t, newStore)
		in := newTenant("acme")
		mustNoErr(t, s.Tenants().Create(ctx, in))
		in.Domains[0] = "mutated.example.test"

		got, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		got.Domains[0] = "mutated-again.example.test"

		again, err := s.Tenants().Get(ctx, "ten_acme")
		mustNoErr(t, err)
		mustEqual(t, again.Domains, []string{"acme.example.test"})
	})
}
