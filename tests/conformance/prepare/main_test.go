package main

import (
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"testing"
	"time"
)

func TestPrepareConformanceFixtures(t *testing.T) {
	st := memory.New()
	defer st.Close()
	ctx := t.Context()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "t", Name: "conformance"}); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"conformance@example.com", "acr-basic@example.com", "acr-formpost@example.com"} {
		if err := st.Users().Create(ctx, &store.User{TenantID: "t", UserID: "auth0|" + email, Email: email, Identities: []store.Identity{{Connection: "Username-Password-Authentication", Provider: "auth0", UserID: email}}}); err != nil {
			t.Fatal(err)
		}
	}
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	fixture := fixtureInput{RecoveryBasic: secrets.RandomString(24), RecoveryFormpost: secrets.RandomString(24)}
	if err := prepare(ctx, st, wrapper, "conformance", fixture, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	g, _ := st.MFA().GetGuardian(ctx, "t")
	if !g.Factors["recovery-code"] {
		t.Fatal("recovery proof is not an enabled factor")
	}
	u, _ := st.Users().FindByLogin(ctx, "t", "Username-Password-Authentication", "conformance@example.com")
	if u.PhoneNumber == "" || u.OwnIdentity().ProviderData["address"] == nil {
		t.Fatal("missing standard claims")
	}
	for _, email := range []string{"acr-basic@example.com", "acr-formpost@example.com"} {
		u, _ := st.Users().FindByLogin(ctx, "t", "Username-Password-Authentication", email)
		aa, err := st.MFA().ListAuthenticators(ctx, "t", u.UserID)
		if err != nil || len(aa) != 2 {
			t.Fatal("MFA fixture is not enrolled", err)
		}
	}
	u, _ = st.Users().FindByLogin(ctx, "t", "Username-Password-Authentication", "acr-basic@example.com")
	service := mfa.NewService(st, wrapper, nil, nil, nil, time.Now)
	if _, err := service.Recover(ctx, "t", u.UserID, fixture.RecoveryBasic); err != nil {
		t.Fatal("fixture proof refused", err)
	}
	if err := prepare(ctx, st, wrapper, "other-tenant", fixture, time.Now()); err == nil {
		t.Fatal("unrelated tenant accepted")
	}
}
