package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"unicode/utf8"
)

type JWTConfiguration struct {
	Alg               string `yaml:"alg"`
	LifetimeInSeconds *int   `yaml:"lifetime_in_seconds"`
}

func (c *Client) validateOIDC() []error {
	c.oidcLogout = nil
	c.oidcSupport = nil
	var errs []error
	if c.OIDCLogout != nil {
		raw, err := json.Marshal(c.OIDCLogout)
		if err == nil {
			c.oidcLogout, err = clientrules.ParseOIDCLogout(raw)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("oidc_logout: %w", err))
		}
	}
	if c.OIDCSupport != nil {
		raw, err := json.Marshal(c.OIDCSupport)
		if err == nil {
			c.oidcSupport, err = clientrules.ParseOIDCSupport(raw)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("oidc_support: %w", err))
		}
	}
	if c.JWTConfiguration != nil {
		if c.JWTConfiguration.LifetimeInSeconds != nil && c.IDTokenLifetime != 0 && *c.JWTConfiguration.LifetimeInSeconds != c.IDTokenLifetime {
			errs = append(errs, errors.New("conflicting ID token lifetimes"))
		}
		if c.JWTConfiguration.Alg == "HS256" {
			if c.usesPrivateKeyJWT() {
				errs = append(errs, errors.New("HS256 requires client-secret authentication"))
			}
			if c.ClientSecret != "" && utf8.RuneCountInString(c.ClientSecret) < 32 {
				errs = append(errs, errors.New("HS256 requires a client secret of at least 32 characters"))
			}
		}
	}
	return errs
}
func checkOIDCStorage(ctx context.Context, st store.Store, f *File) error {
	for _, t := range f.Tenants {
		for _, c := range t.Clients {
			if c.oidcLogout != nil || c.oidcSupport != nil || c.JWTConfiguration != nil && c.JWTConfiguration.Alg != "" && c.JWTConfiguration.Alg != "RS256" {
				return store.CheckOIDCLogoutSupport(ctx, st)
			}
		}
	}
	return nil
}
