package emailrules

import (
	"context"
	"encoding/json"
	"errors"
	"maps"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var publicCredentialFields = [...]string{"api_user", "region", "smtp_host", "smtp_port", "smtp_user"}

// Copy only typed scalar members. Unknown fields stay private, including
// credentials introduced by plugins or newer versions of a provider.
func publicCredentials(src map[string]any) (map[string]any, error) {
	out := make(map[string]any)
	for _, key := range publicCredentialFields {
		v, ok := src[key]
		if !ok || v == nil {
			continue
		}
		if key == "smtp_port" {
			switch port := v.(type) {
			case float64:
				if port < 1 || port > 65535 || port != float64(int(port)) {
					return nil, ErrInvalidProvider
				}
			case int:
				if port < 1 || port > 65535 {
					return nil, ErrInvalidProvider
				}
			default:
				return nil, ErrInvalidProvider
			}
		} else if _, ok := v.(string); !ok {
			return nil, ErrInvalidProvider
		}
		out[key] = v
	}
	return out, nil
}

// OpenCredentials reads the effective credential set for a partial update.
// Sealed members take precedence on legacy rows that duplicated a setting.
func OpenCredentials(w keys.Wrapper, tenantID string, p *store.EmailProvider) (map[string]any, error) {
	creds, err := publicCredentials(p.PublicConfig)
	if err != nil {
		return nil, err
	}
	if len(p.SealedCredentials) == 0 {
		return creds, nil
	}
	b, err := keys.OpenEmailProvider(w, tenantID, p.Name, p.SealedCredentials)
	if err != nil {
		return nil, err
	}
	var stored map[string]any
	if json.Unmarshal(b, &stored) != nil || stored == nil {
		return nil, ErrInvalidProvider
	}
	maps.Copy(creds, stored)
	return creds, nil
}

// Replace just the public credential members. Keep unrelated provider settings
// (for example SMTP headers) and honor explicit clears in the credential set.
func configWithCredentials(config, creds map[string]any) (map[string]any, error) {
	public, err := publicCredentials(creds)
	if err != nil {
		return nil, err
	}
	next := maps.Clone(config)
	if next == nil {
		return public, nil
	}
	for _, k := range publicCredentialFields {
		delete(next, k)
	}
	maps.Copy(next, public)
	return next, nil
}

// SealCredentials partitions a validated effective credential set into the two
// columns persisted together by EmailProviders.Put's revision check.
func SealCredentials(w keys.Wrapper, p *store.EmailProvider, creds map[string]any) error {
	config, err := configWithCredentials(p.PublicConfig, creds)
	if err != nil {
		return err
	}
	private := maps.Clone(creds)
	for _, k := range publicCredentialFields {
		delete(private, k)
	}
	b, err := json.Marshal(private)
	if err != nil {
		return ErrInvalidProvider
	}
	sealed, err := keys.SealEmailProviderSecrets(w, p.TenantID, p.Name, b)
	if err != nil {
		return err
	}
	p.PublicConfig, p.SealedCredentials = config, sealed
	return nil
}

// LegacyPublicConfig reconstructs the public view on a legacy read without
// changing the row. Tagged rows already hold every public field in PublicConfig.
func LegacyPublicConfig(w keys.Wrapper, tenantID string, p *store.EmailProvider) error {
	if keys.EmailProviderSecretsOnly(p.SealedCredentials) || len(p.SealedCredentials) == 0 {
		return nil
	}
	creds, err := OpenCredentials(w, tenantID, p)
	if err != nil {
		return err
	}
	config, err := configWithCredentials(p.PublicConfig, creds)
	if err != nil {
		return err
	}
	p.PublicConfig = config
	return nil
}

// BackfillProvider migrates one tenant. Concurrent writers win the revision
// check, so a retry always reads the current provider and its current kind.
func BackfillProvider(ctx context.Context, repo store.EmailProviders, w keys.Wrapper, tenantID string) error {
	for range 3 {
		p, err := repo.Get(ctx, tenantID)
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrEmailRepositoryUnavailable) || status.Code(err) == codes.Unimplemented {
			return nil
		}
		if err != nil {
			return err
		}
		if len(p.SealedCredentials) == 0 || keys.EmailProviderSecretsOnly(p.SealedCredentials) {
			return nil
		}
		creds, err := OpenCredentials(w, tenantID, p)
		if err != nil {
			return err
		}
		if p.TenantID != tenantID {
			return ErrInvalidProvider
		}
		next := *p
		if err := SealCredentials(w, &next, creds); err != nil {
			return err
		}
		if err := repo.Put(ctx, &next, p.Revision); !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return store.ErrConflict
}
