// Package exchangerules holds the rules for token exchange profiles that the
// Management API and the seed share.
package exchangerules

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	// MaxProfiles is the local per-tenant limit (C8).
	MaxProfiles = 100
	// TypeCustomAuthentication is the only profile type.
	TypeCustomAuthentication = "custom_authentication"

	minName             = 3
	maxName             = 50
	minSubjectTokenType = 8
	maxSubjectTokenType = 100
)

// reservedSubjectTokenTypes are the prefixes a profile may not claim.
var reservedSubjectTokenTypes = []string{
	"http://auth0.com", "https://auth0.com", "http://okta.com", "https://okta.com",
	"urn:ietf", "urn:auth0", "urn:okta",
}

// ValidateName checks a profile name.
func ValidateName(name string) error {
	if n := utf8.RuneCountInString(name); n < minName || n > maxName {
		return fmt.Errorf("name must be %d to %d characters", minName, maxName)
	}
	return nil
}

// ValidateSubjectTokenType checks a profile's subject_token_type.
func ValidateSubjectTokenType(t string) error {
	if n := utf8.RuneCountInString(t); n < minSubjectTokenType || n > maxSubjectTokenType {
		return fmt.Errorf("subject_token_type must be %d to %d characters", minSubjectTokenType, maxSubjectTokenType)
	}
	if !strings.HasPrefix(t, "https://") && !strings.HasPrefix(t, "urn:") {
		return fmt.Errorf("subject_token_type must begin with https:// or urn:")
	}
	lower := strings.ToLower(t)
	for _, p := range reservedSubjectTokenTypes {
		if strings.HasPrefix(lower, p) {
			return fmt.Errorf("subject_token_type begins with the reserved prefix %s", p)
		}
	}
	return nil
}
