package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func testDPoP(t *testing.T, newStore Factory) {
	ctx := context.Background()
	t.Run("Replay", func(t *testing.T) {
		s := open(t, newStore)
		at := ts(0)
		use := func(repo store.DPoP, tenant, origin, key string, now time.Time) error {
			return repo.UseProof(ctx, tenant, origin, key, "proof-id", now, now.Add(time.Minute))
		}
		for _, v := range []struct{ tid, origin, key string }{{"ten_a", "https://a.test", "key"}, {"ten_b", "https://a.test", "key"}, {"ten_a", "https://b.test", "key"}, {"ten_a", "https://a.test", "other"}} {
			mustNoErr(t, use(s.DPoP(), v.tid, v.origin, v.key, at))
			mustErrIs(t, use(s.DPoP(), v.tid, v.origin, v.key, at), store.ErrConflict)
		}
		rollback := errors.New("rollback")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := use(tx.DPoP(), "ten_a", "https://a.test", "rolled-back", at); err != nil {
				return err
			}
			return rollback
		})
		mustErrIs(t, err, rollback)
		mustNoErr(t, use(s.DPoP(), "ten_a", "https://a.test", "rolled-back", at))
		at = at.Add(time.Minute)
		mustNoErr(t, use(s.DPoP(), "ten_a", "https://a.test", "key", at))
		n, err := s.DPoP().PurgeBefore(ctx, at, 2)
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		n, err = s.DPoP().PurgeBefore(ctx, at, 20)
		mustNoErr(t, err)
		mustEqual(t, n, 2)
		mustErrIs(t, use(s.DPoP(), "ten_a", "https://a.test", "key", at), store.ErrConflict)
	})
	t.Run("Concurrent", func(t *testing.T) {
		s := open(t, newStore)
		errs := parallel(8, func(int) error {
			return s.DPoP().UseProof(ctx, "ten_a", "https://a.test", "key", "proof-id", ts(0), ts(time.Minute))
		})
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else {
				mustErrIs(t, err, store.ErrConflict)
			}
		}
		mustEqual(t, wins, 1)
	})
	t.Run("BindingsAndConfig", func(t *testing.T) {
		s := open(t, newStore)
		tx := newAuthTransaction("ten_a", "tx")
		tx.DPoPJKT = "key"
		mustNoErr(t, s.AuthTransactions().Create(ctx, tx))
		tx, err := s.AuthTransactions().Get(ctx, "ten_a", "tx")
		mustNoErr(t, err)
		mustEqual(t, tx.DPoPJKT, "key")
		code := newAuthCode("ten_a", "code")
		code.DPoPJKT = "key"
		mustNoErr(t, s.AuthCodes().Create(ctx, code))
		code, err = s.AuthCodes().Consume(ctx, "ten_a", "code", ts(time.Minute))
		mustNoErr(t, err)
		mustEqual(t, code.DPoPJKT, "key")
		c := newClient("ten_a", "client")
		c.RequireProofOfPossession = true
		c.RefreshToken.Policies = []store.MRRTPolicy{{Audience: "api", Scope: []string{"read"}}}
		c.TokenQuota = &store.TokenQuota{PerHour: 11, Enforce: true}
		mustNoErr(t, s.Clients().Create(ctx, c))
		c.RefreshToken.Policies[0].Scope[0] = "changed"
		c.TokenQuota.PerHour = 0
		c, err = s.Clients().Get(ctx, "ten_a", "client")
		mustNoErr(t, err)
		mustEqual(t, c.RequireProofOfPossession, true)
		mustEqual(t, c.RefreshToken.Policies, []store.MRRTPolicy{{Audience: "api", Scope: []string{"read"}}})
		mustEqual(t, c.TokenQuota, &store.TokenQuota{PerHour: 11, Enforce: true})
		rs := newResourceServer("ten_a", "rs", "https://api.test")
		rs.ProofOfPossession = &store.ProofOfPossession{Mechanism: "dpop", Required: true, RequiredFor: "public_clients"}
		rs.AllowOnlineAccess = true
		rs.AllowOnlineAccessWithEphemeralSessions = true
		mustNoErr(t, s.ResourceServers().Create(ctx, rs))
		rs.ProofOfPossession.Required = false
		rs, err = s.ResourceServers().Get(ctx, "ten_a", "rs")
		mustNoErr(t, err)
		mustEqual(t, rs.ProofOfPossession, &store.ProofOfPossession{Mechanism: "dpop", Required: true, RequiredFor: "public_clients"})
		mustEqual(t, rs.AllowOnlineAccess, true)
		mustEqual(t, rs.AllowOnlineAccessWithEphemeralSessions, true)
		tenant := newTenant("quota")
		tenant.DefaultTokenQuota = &store.DefaultTokenQuota{Clients: &store.TokenQuota{PerHour: 11}, Organizations: &store.TokenQuota{PerDay: 20}}
		mustNoErr(t, s.Tenants().Create(ctx, tenant))
		tenant.DefaultTokenQuota.Clients.PerHour = 0
		tenant.DefaultTokenQuota.Organizations.PerDay = 0
		tenant, err = s.Tenants().Get(ctx, tenant.ID)
		mustNoErr(t, err)
		mustEqual(t, tenant.DefaultTokenQuota.Clients.PerHour, 11)
		mustEqual(t, tenant.DefaultTokenQuota.Organizations.PerDay, 20)
		org := newOrg(tenant.ID, "quota", ts(0))
		org.TokenQuota = &store.TokenQuota{PerDay: 4}
		mustNoErr(t, s.Organizations().Create(ctx, org, nil))
		org.TokenQuota.PerDay = 1
		org, err = s.Organizations().Get(ctx, tenant.ID, org.ID)
		mustNoErr(t, err)
		mustEqual(t, org.TokenQuota.PerDay, 4)
	})
}
