package federation

import (
	"context"
	"errors"
	"testing"
)

func TestOIDCValidationRejectsIssuerTemplates(t *testing.T) {
	for _, issuer := range []string{
		"https://login.microsoftonline.com/{tenantid}/v2.0",
		"https://login.microsoftonline.com/%7Btenantid%7D/v2.0",
		"https://issuer.example/{tenant}/v2.0",
	} {
		t.Run(issuer, func(t *testing.T) {
			p := newIDP(t)
			p.meta = func(m map[string]any) { m["issuer"] = issuer }
			if _, err := p.providers().Discover(context.Background(), CacheKey{}, p.issuer()+"/.well-known/openid-configuration", ""); !errors.Is(err, ErrProviderResponse) {
				t.Fatalf("template accepted: %v", err)
			}
		})
	}
}
