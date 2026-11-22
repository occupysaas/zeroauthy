package clientrules

import (
	"errors"
	"unicode/utf8"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func validateMRRT(policies []store.MRRTPolicy, firstParty bool) error {
	if policies == nil {
		return nil
	}
	if !firstParty {
		return errors.New("refresh_token.policies require a first-party client")
	}
	if len(policies) == 0 || len(policies) > 10 {
		return errors.New("refresh_token.policies must contain 1 to 10 policies")
	}
	seen := make(map[string]bool, len(policies))
	for _, p := range policies {
		if n := utf8.RuneCountInString(p.Audience); n < 1 || n > 600 {
			return errors.New("refresh token policy audience must be 1 to 600 characters")
		}
		if p.Audience == tenant.OperatorAudience {
			return errors.New("a refresh token policy cannot target the operator API")
		}
		if seen[p.Audience] {
			return errors.New("refresh token policy audiences must be unique")
		}
		seen[p.Audience] = true
		if p.Scope == nil {
			return errors.New("refresh token policy scope must be an array")
		}
		for _, scope := range p.Scope {
			if n := utf8.RuneCountInString(scope); n < 1 || n > 280 {
				return errors.New("refresh token policy scope must be 1 to 280 characters")
			}
		}
	}
	return nil
}

// CheckMRRTManagementAudience checks the tenant-dependent exclusion once the
// canonical Management API identifier is available.
func CheckMRRTManagementAudience(policies []store.MRRTPolicy, managementAudience string) error {
	for _, p := range policies {
		if managementAudience != "" && p.Audience == managementAudience {
			return errors.New("a refresh token policy cannot target the Management API")
		}
	}
	return nil
}
