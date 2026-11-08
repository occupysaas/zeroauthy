package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// parseMobile checks a seeded client mobile object with the Management API's
// rules (clientrules.ParseMobile). Unlike the API, which ignores unknown
// properties, the seed refuses them, as it refuses every unknown seed key.
func parseMobile(raw map[string]any) (*store.ClientMobile, error) {
	known := map[string][]string{
		"ios":     {"team_id", "app_bundle_identifier"},
		"android": {"app_package_name", "sha256_cert_fingerprints"},
	}
	for platform, value := range raw {
		keys, ok := known[platform]
		if !ok {
			return nil, fmt.Errorf("mobile has unknown property %q", platform)
		}
		object, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mobile.%s must be an object", platform)
		}
		for key := range object {
			if !slices.Contains(keys, key) {
				return nil, fmt.Errorf("mobile.%s has unknown property %q", platform, key)
			}
		}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("mobile: %w", err)
	}
	m, err := clientrules.ParseMobile(b)
	if err != nil {
		return nil, fmt.Errorf("mobile: %w", err)
	}
	return m, nil
}

// validateRoamingUV checks guardian.webauthn_roaming against the values the
// operator extension route accepts.
func validateRoamingUV(in *Tenant) error {
	guardian, _ := in.supplied["guardian"].(map[string]any)
	raw, ok := guardian["webauthn_roaming"]
	if !ok {
		return nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return errors.New("webauthn_roaming must be an object")
	}
	switch object["user_verification"] {
	case "discouraged", "preferred", "required":
		return nil
	}
	return errors.New("webauthn_roaming.user_verification must be discouraged, preferred or required")
}

// usesWebAuthnStorage reports seeded fields a store without webauthn.v1 would
// drop on write: client mobile settings and alias RP IDs. Connection passkey
// options, the passkey grant and security-key user verification are stored
// configuration that an older plugin keeps unchanged.
func usesWebAuthnStorage(f *File) bool {
	for _, t := range f.Tenants {
		if len(t.DomainRPIDs) > 0 {
			return true
		}
		for _, c := range t.Clients {
			if c.mobile != nil {
				return true
			}
		}
	}
	return false
}

// checkWebAuthnStorage refuses those fields on a plugin store that did not
// negotiate webauthn.v1, rather than letting the write drop them silently.
func checkWebAuthnStorage(ctx context.Context, st store.Store, f *File) error {
	if !usesWebAuthnStorage(f) {
		return nil
	}
	capable, ok := st.(store.WebAuthnSupporter)
	if !ok {
		return nil
	}
	if err := capable.CheckWebAuthnSupport(ctx); err != nil {
		if errors.Is(err, store.ErrWebAuthnUnavailable) {
			return fmt.Errorf("seed: client mobile settings and domain relying_party_identifier need a store plugin with webauthn.v1: %w", err)
		}
		return err
	}
	if !capable.WebAuthnSupported() {
		return fmt.Errorf("seed: client mobile settings and domain relying_party_identifier need a store plugin with webauthn.v1: %w", store.ErrWebAuthnUnavailable)
	}
	return nil
}
