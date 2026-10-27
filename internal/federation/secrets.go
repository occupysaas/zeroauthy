package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// credentialsLabel versions the sealed credential format; it is part of the
// AAD with the tenant and connection IDs.
const credentialsLabel = "federation-credentials/v1"

// Credentials are a federated connection's provider secrets.
type Credentials struct {
	ClientSecret string `json:"client_secret"`
}

// SealCredentials encrypts c bound to its tenant and connection.
func SealCredentials(w keys.Wrapper, tenantID, connectionID string, c Credentials) ([]byte, error) {
	if c.ClientSecret == "" {
		return nil, errors.New("federation: empty client secret")
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return nil, errors.New("federation: encode credentials")
	}
	return keys.SealBound(w, credentialsLabel, []string{tenantID, connectionID}, plain)
}

// OpenCredentials reverses SealCredentials. Errors never contain secrets.
func OpenCredentials(w keys.Wrapper, tenantID, connectionID string, sealed []byte) (Credentials, error) {
	var c Credentials
	plain, err := keys.OpenBound(w, credentialsLabel, []string{tenantID, connectionID}, sealed)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(plain, &c); err != nil || c.ClientSecret == "" {
		return Credentials{}, errors.New("federation: malformed credentials")
	}
	return c, nil
}

// ApplyConnection completes a write of a federated connection after spec was
// normalized and connrules.Apply copied it into next. prev is the stored
// connection on update and nil on create. It enforces the immutable
// bindings, seals a supplied plaintext secret (removing it from next.Extra),
// preserves an omitted one, and sets FederationRevision: 1 on create, one
// more on any effective authentication change. Errors wrapping ErrImmutable
// or ErrInvalidConfig are the caller's 400s.
func ApplyConnection(w keys.Wrapper, prev *store.Connection, spec *connrules.Spec, next *store.Connection) error {
	if !spec.Federated() {
		return nil
	}
	secret, named := rules.ClientSecret(spec.Options.Extra)
	delete(next.Extra, "client_secret")
	if prev != nil && spec.FederationIssuer == "" {
		connrules.KeepFederationIssuer(prev, next)
		spec.FederationIssuer = connrules.FromConnection(next).FederationIssuer
	}
	cfg, err := ParseConfig(*spec)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if named {
		sealed, err := sealUnlessSame(w, prev, next, secret)
		if err != nil {
			return err
		}
		next.FederationSecretsSealed = sealed
	} else if prev != nil {
		next.FederationSecretsSealed = slices.Clone(prev.FederationSecretsSealed)
	}
	if len(next.FederationSecretsSealed) == 0 {
		return fmt.Errorf("%w: options.client_secret is required", ErrInvalidConfig)
	}
	cfg.SecretReference = slices.Clone(next.FederationSecretsSealed)
	if prev == nil {
		next.FederationRevision = 1
		return nil
	}
	prevSpec := connrules.FromConnection(prev)
	prevCfg, err := ParseConfig(*prevSpec)
	if err != nil {
		return fmt.Errorf("%w: stored configuration: %v", ErrInvalidConfig, err)
	}
	if err := ValidateConfigUpdate(prevCfg, cfg); err != nil {
		return err
	}
	next.FederationRevision = prev.FederationRevision
	if EffectiveChange(prevCfg, cfg) || !sameSet(prev.EnabledClients, next.EnabledClients) {
		next.FederationRevision++
	}
	return nil
}

// ErrInvalidConfig reports a federated configuration that fails validation.
var ErrInvalidConfig = errors.New("federation: invalid connection configuration")

// sealUnlessSame seals secret for next, reusing prev's sealed bytes when they
// already hold the same secret, so an unchanged write is not a rotation.
func sealUnlessSame(w keys.Wrapper, prev, next *store.Connection, secret string) ([]byte, error) {
	if w == nil {
		return nil, errors.New("federation: no master key wrapper to seal provider credentials")
	}
	if prev != nil && len(prev.FederationSecretsSealed) > 0 {
		if c, err := OpenCredentials(w, prev.TenantID, prev.ID, prev.FederationSecretsSealed); err == nil && c.ClientSecret == secret {
			return slices.Clone(prev.FederationSecretsSealed), nil
		}
	}
	return SealCredentials(w, next.TenantID, next.ID, Credentials{ClientSecret: secret})
}

// BumpForEnablement returns the revision after an enabled-clients change of
// a federated connection: enablement is effective configuration.
func BumpForEnablement(prev []string, next *store.Connection) {
	if rules.IsFederated(next.Strategy) && !sameSet(prev, next.EnabledClients) {
		next.FederationRevision++
	}
}

// PinIssuer durably pins an OIDC connection's issuer on its first successful
// discovery, under a compare-and-swap on the connection revision. It returns
// the connection's revision afterwards: unchanged when the same issuer is
// already pinned, one more when this call pinned it. A stale revision is
// store.ErrConflict (restart the attempt); a different pinned issuer wraps
// ErrImmutable.
func PinIssuer(ctx context.Context, st store.Store, tenantID, connectionID string, expectedRevision int64, issuer string) (int64, error) {
	var rev int64
	err := st.WithTx(ctx, func(tx store.Store) error {
		c, err := tx.Connections().Get(ctx, tenantID, connectionID)
		if err != nil {
			return err
		}
		if c.Strategy != StrategyOIDC {
			cfg, err := ParseConfig(*connrules.FromConnection(c))
			tid, concrete := microsoftIssuerTenant(issuer)
			if err != nil || cfg.Strategy != StrategyWAAD || cfg.MicrosoftMultiTenant || !concrete || tid == microsoftConsumerTenant {
				return fmt.Errorf("%w: connection cannot pin issuer", ErrInvalidConfig)
			}
			if err := RequireMicrosoftFederation(ctx, tx); err != nil {
				return err
			}
		}
		if c.FederationRevision != expectedRevision {
			return store.ErrConflict
		}
		spec := connrules.FromConnection(c)
		switch spec.FederationIssuer {
		case issuer:
			rev = c.FederationRevision
			return nil
		case "":
		default:
			return fmt.Errorf("%w: issuer", ErrImmutable)
		}
		spec.FederationIssuer = issuer
		next := *c
		connrules.Apply(spec, &next)
		next.FederationRevision++
		rev = next.FederationRevision
		return tx.Connections().Update(ctx, &next)
	})
	return rev, err
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
