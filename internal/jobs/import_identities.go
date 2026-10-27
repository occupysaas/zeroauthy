package jobs

import (
	"context"
	"errors"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// secondaryImportIdentities is the local explicit migration subset: canonical
// federated connection/provider/user_id triples on a database-root import.
// Credentials and provider profile fields cannot be injected through this path.
func secondaryImportIdentities(raw any) ([]store.Identity, []store.JobErrorItem) {
	fail := func() ([]store.Identity, []store.JobErrorItem) {
		return nil, []store.JobErrorItem{item("INVALID_FORMAT", "identities must contain at most 100 canonical secondary federated connection/provider/user_id objects", "identities")}
	}
	list, ok := raw.([]any)
	if !ok || len(list) > 100 {
		return fail()
	}
	ids := make([]store.Identity, 0, len(list))
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok || len(obj) != 3 {
			return fail()
		}
		conn, ok1 := obj["connection"].(string)
		provider, ok2 := obj["provider"].(string)
		id, ok3 := obj["user_id"].(string)
		if !ok1 || !ok2 || !ok3 || conn == "" || !store.IsFederatedProvider(provider) {
			return fail()
		}
		ids = append(ids, store.Identity{Connection: conn, Provider: provider, UserID: id, ProfileData: map[string]any{}})
	}
	return ids, nil
}

func resolveImportIdentities(ctx context.Context, tx store.Store, tenant string, ids []store.Identity) ([]store.FederatedIdentityKey, error) {
	for _, id := range ids {
		if id.Provider == "windowslive" || id.Provider == "waad" {
			if err := federation.RequireMicrosoftFederation(ctx, tx); err != nil {
				return nil, err
			}
			break
		}
	}
	return store.ResolveFederatedKeys(&store.User{TenantID: tenant, Identities: ids}, func(name string) (*store.Connection, error) { return tx.Connections().GetByName(ctx, tenant, name) })
}

func validateImportIdentities(ctx context.Context, tx store.Store, tenant string, f *fields) ([]store.JobErrorItem, error) {
	keys, err := resolveImportIdentities(ctx, tx, tenant, f.identities)
	if errors.Is(err, store.ErrInvalid) || errors.Is(err, store.ErrFederationUnavailable) || err == nil && len(keys) != len(f.identities) {
		return []store.JobErrorItem{item("INVALID_FORMAT", "Secondary federated identities cannot be resolved; verify connection, provider, canonical identity encoding and store capability", "identities")}, nil
	}
	if err != nil {
		return nil, err
	}
	f.identityKeys = keys
	return nil, nil
}

func matchingImportIdentities(ctx context.Context, tx store.Store, u *store.User, f *fields) (bool, error) {
	keys, err := store.ResolveFederatedKeys(u, func(name string) (*store.Connection, error) { return tx.Connections().GetByName(ctx, u.TenantID, name) })
	return slices.Equal(keys, f.identityKeys), err
}
