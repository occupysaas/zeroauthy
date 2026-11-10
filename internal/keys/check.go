package keys

import (
	"context"
	"fmt"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// CheckMasterKey verifies that w can open the stored signing keys. It looks
// at one key per tenant that has any (every key of a store is sealed under
// the same master key) and fails on the first one that does not decrypt, so
// a wrong or rotated-away master key is reported at startup instead of
// surfacing later as failed token requests. A store without signing keys
// passes: there is nothing to contradict the key.
func CheckMasterKey(ctx context.Context, st store.Store, w Wrapper) error {
	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return err
	}
	for _, t := range tenants {
		ks, err := st.SigningKeys().List(ctx, t.ID)
		if err != nil {
			return err
		}
		if len(ks) == 0 {
			continue
		}
		k := ks[0]
		if _, err := unseal(w, k.PrivateKey, aad(k.TenantID, k.KID)); err != nil {
			return fmt.Errorf("keys: the master key cannot decrypt signing key %s of tenant %s (wrong security.master_key or master_key_file for this database?): %w", k.KID, t.ID, err)
		}
	}
	return nil
}
