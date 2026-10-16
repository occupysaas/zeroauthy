package access

// Values Auth0's documentation leaves open, settled by observation on the
// maintainer's tenant (docs/compat/observations/consent.md, D-0025–D-0027).
// Change them only together with those records.
const (
	// O5: prompt=none when consent or the confirmation would be needed.
	codeConsentRequired      = "consent_required"
	codeConfirmationRequired = "consent_required"
	// O7: a user flow refused by the API's access policy (HTTP 400 at the
	// token endpoint).
	codeAuthorizeDenied = "invalid_request"
	codeTokenDenied     = "invalid_request"
	// O2b: a strict client that names no audience.
	codeStrictNoAudience = "invalid_request"
	// O8 (not observable; permissive-mode page): a permissive third-party
	// client may use an allow_all API without a client grant.
	permissiveFollowsPolicy = true
	// O4: a first-party client of an API that skips consent gets the
	// confirmation, not consent, for a non-verifiable callback.
	firstPartyNonVerifiableConsent = false
	// O2 (not observable; permissive only): a third-party request with no
	// audience asks consent.
	consentWithoutAudience = true
	// O3: accepting consent adds to a grant's scopes.
	mergeGrantScopes = true
)
