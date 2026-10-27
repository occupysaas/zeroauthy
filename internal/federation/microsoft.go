package federation

import (
	"context"
	"net/url"
)

// microsoftProvider uses validated attempt endpoints and Microsoft-only issuer
// policy. It returns a verified identity without provisioning or persisting it.
type microsoftProvider struct{ ps *Providers }

func (p microsoftProvider) AuthorizationURL(in StartInput) (string, error) {
	raw, err := authorizationURL(in.Endpoints.AuthorizationURL, in.Config, in, true)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_mode", "query")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p microsoftProvider) Exchange(ctx context.Context, in ExchangeInput) (ProviderResult, error) {
	tokens, err := p.ps.exchangeCode(ctx, in.Endpoints.TokenURL, authPost, in)
	if err != nil {
		return ProviderResult{}, err
	}
	obj, err := parseIDToken(tokens.IDToken)
	if err != nil {
		return ProviderResult{}, err
	}
	// Unverified claims can only narrow key eligibility. The network/cache inputs
	// come exclusively from validated configuration and the attempt snapshot.
	unverified, err := decodeIDTokenClaims(obj.UnsafePayloadWithoutVerification())
	if err != nil {
		return ProviderResult{}, err
	}
	issuer, _ := unverified["iss"].(string)
	tenant, _ := unverified["tid"].(string)
	selected, err := p.ps.microsoftSigningKey(ctx, in.Cache, in.Config.MicrosoftAuthority, in.Endpoints.JWKSURL, obj.Signatures[0].Header.KeyID, issuer, tenant)
	if err != nil {
		return ProviderResult{}, err
	}
	payload, err := obj.Verify(&selected.Key)
	if err != nil {
		return ProviderResult{}, idTokenError("signature is invalid")
	}
	claims, err := decodeIDTokenClaims(payload)
	if err != nil {
		return ProviderResult{}, err
	}
	now := p.ps.exchangeTime(in)
	if err := validateMicrosoftClaims(in.Config, in.Issuer, selected.Issuer, claims, now); err != nil {
		return ProviderResult{}, err
	}
	if err := validateIDTokenClaims(in, tokens, claims, now); err != nil {
		return ProviderResult{}, err
	}
	profile, err := microsoftProfile(in.Config, claims)
	if err != nil {
		return ProviderResult{}, err
	}
	return ProviderResult{Profile: profile, Tokens: tokens}, nil
}
