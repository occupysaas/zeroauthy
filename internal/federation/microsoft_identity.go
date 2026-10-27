package federation

import (
	"fmt"
	"strings"
	"time"
)

// validateMicrosoftClaims binds only verified claims to the attempt policy and
// the retained signing-key issuer. No claim chooses an endpoint or cache scope.
func validateMicrosoftClaims(cfg Config, expectedIssuer, keyIssuer string, claims map[string]any, now time.Time) error {
	bad := func(what string) error { return fmt.Errorf("%w: Microsoft ID token %s", ErrProviderResponse, what) }
	tid, _ := claims["tid"].(string)
	issuer, _ := claims["iss"].(string)
	if claims["ver"] != "2.0" || !canonicalMicrosoftGUID.MatchString(tid) || issuer != microsoftTenantIssuer(tid) {
		return bad("version, tenant or issuer is invalid")
	}
	if keyIssuer != issuer && keyIssuer != microsoftIssuerTemplate {
		return bad("signing-key issuer mismatch")
	}
	if !validMicrosoftAuthority(cfg.MicrosoftAuthority) || cfg.MicrosoftMultiTenant != (cfg.MicrosoftAuthority == "organizations") {
		return bad("authority policy is invalid")
	}
	switch cfg.Strategy {
	case StrategyWindowsLive:
		if cfg.MicrosoftAuthority != "consumers" || tid != microsoftConsumerTenant || (expectedIssuer != issuer && expectedIssuer != microsoftIssuerTemplate) {
			return bad("personal tenant mismatch")
		}
	case StrategyWAAD:
		if tid == microsoftConsumerTenant || cfg.MicrosoftAuthority == "consumers" {
			return bad("organizational tenant required")
		}
		if cfg.MicrosoftMultiTenant {
			if expectedIssuer != microsoftIssuerTemplate {
				return bad("organizational issuer policy mismatch")
			}
		} else {
			if expectedIssuer != issuer || (canonicalMicrosoftGUID.MatchString(cfg.MicrosoftAuthority) && tid != cfg.MicrosoftAuthority) {
				return bad("directory issuer mismatch")
			}
		}
	default:
		return bad("strategy is invalid")
	}
	if value, present := claims["nbf"]; present {
		nbf, ok := numericDate(value)
		if !ok || nbf.After(now.Add(clockSkew)) {
			return bad("is not yet valid")
		}
	}
	return nil
}

// microsoftSubject is called only after full ID-token verification. Arbitrary
// personal sub bytes remain intact; only organizational GUIDs are normalized.
func microsoftSubject(cfg Config, claims map[string]any) (string, error) {
	sub, _ := claims["sub"].(string)
	if err := ValidateSubject(sub); err != nil {
		return "", idTokenError("subject is missing or invalid")
	}
	if cfg.Strategy == StrategyWindowsLive {
		return sub, nil
	}
	if cfg.Strategy != StrategyWAAD {
		return "", idTokenError("strategy is invalid")
	}
	oid, _ := claims["oid"].(string)
	oid = strings.ToLower(oid)
	if !canonicalMicrosoftGUID.MatchString(oid) {
		return "", idTokenError("object ID is missing or invalid")
	}
	if cfg.MicrosoftMultiTenant {
		tid, _ := claims["tid"].(string)
		if !canonicalMicrosoftGUID.MatchString(tid) || tid == microsoftConsumerTenant {
			return "", idTokenError("tenant is invalid")
		}
		return tid + ":" + oid, nil
	}
	return oid, nil
}

func microsoftProfile(cfg Config, claims map[string]any) (Profile, error) {
	sub, err := microsoftSubject(cfg, claims)
	if err != nil {
		return Profile{}, err
	}
	allowed := map[string]any{}
	for _, k := range []string{"email", "name", "given_name", "family_name"} {
		if v, present := claims[k]; present {
			allowed[k] = v
		}
	}
	// Explicit false prevents previous verification from surviving a new address,
	// including optional upstream email_verified=true claims we do not trust.
	allowed["email_verified"] = false
	return profileFromClaims(sub, allowed)
}
