package seed

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func checkDPoPStorage(ctx context.Context, st store.Store, f *File) error {
	for _, t := range f.Tenants {
		for _, c := range t.Clients {
			if c.RequireProofOfPossession {
				if e := store.CheckRefreshTokensIISupport(ctx, st); e != nil {
					return e
				}
			}
		}
		for _, rs := range t.ResourceServers {
			if rs.ProofOfPossession != nil {
				if e := store.CheckRefreshTokensIISupport(ctx, st); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
