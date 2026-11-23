package federation

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// StrategyADFS is the WS-Federation relying-party connection strategy
// (Plan 37b): ADFS or any WS-Fed identity provider.
const StrategyADFS = rules.ADFS

// ErrWSFedResponse is a wresult that failed validation. Details stay in the
// operator log as error classes only.
var ErrWSFedResponse = fmt.Errorf("%w (WS-Federation)", ErrSAMLResponse)

// ADFSEntityID is the relying party identifier sent as wtrealm and required
// as the token audience: options.entityId or urn:auth0:{tenant}:{connection}.
func ADFSEntityID(tenant *store.Tenant, conn *store.Connection, cfg Config) string {
	if cfg.ADFS != nil && cfg.ADFS.EntityID != "" {
		return cfg.ADFS.EntityID
	}
	return "urn:auth0:" + tenant.Name + ":" + conn.Name
}

// adfsSignInURL is the passive requestor sign-in request: wa=wsignin1.0,
// wtrealm = the entity ID, wreply = the callback and wctx = the attempt
// state, which the identity provider returns with the token.
func adfsSignInURL(tenant *store.Tenant, conn *store.Connection, cfg Config, callback, state string) (string, error) {
	u, err := url.Parse(cfg.ADFS.SignInEndpoint)
	if err != nil || u.Host == "" {
		return "", ErrConnectionUnusable
	}
	q := u.Query()
	q.Set("wa", "wsignin1.0")
	q.Set("wtrealm", ADFSEntityID(tenant, conn, cfg))
	q.Set("wreply", callback)
	q.Set("wctx", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// adfsTrust trusts the signing certificates by thumbprint: the current
// ones and those from before the last metadata change. SHA-1 signatures
// are refused (no option selects them, D-0130).
func adfsTrust(s *FlowService, a *rules.ADFSSettings) samlcore.Trust {
	return samlcore.Trust{Thumbprints: slices.Concat(a.Thumbprints, a.PrevThumbprints), Thumbprints384: a.Thumbprints384, Now: s.now}
}

// adfsValidate verifies a posted wresult for conn: a SAML 1.1 or 2.0 token
// signed by a trusted certificate, for the connection's entity ID, within
// its validity window.
func (s *FlowService) adfsValidate(tenant *store.Tenant, conn *store.Connection, cfg Config, raw string) (*samlAssertion, error) {
	a := cfg.ADFS
	if a == nil {
		return nil, ErrConnectionUnusable
	}
	tok, err := samlcore.VerifyWSFedToken([]byte(raw), adfsTrust(s, a))
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrWSFedResponse)
	}
	if err := tok.Check(samlcore.WSFedExpect{Now: s.now(), Skew: samlSkew, Audience: ADFSEntityID(tenant, conn, cfg)}); err != nil {
		return nil, fmt.Errorf("%w: conditions", ErrWSFedResponse)
	}
	profile, err := adfsProfile(a, tok)
	if err != nil {
		return nil, err
	}
	return &samlAssertion{Result: ProviderResult{Profile: profile}, ID: tok.ID, ExpiresAt: tok.NotOnOrAfter.Add(samlSkew),
		NameID: tok.NameID, NameIDFormat: tok.NameIDFormat}, nil
}

// adfsDefaults are the claim types ADFS sends for each profile field
// (Auth0's ADFS claim rules), then short names.
var adfsDefaults = map[string][]string{
	"email":       {samlcore.ClaimEmail, "email"},
	"name":        {samlcore.ClaimName, "name"},
	"given_name":  {samlcore.ClaimGivenName, "given_name"},
	"family_name": {samlcore.ClaimSurname, "family_name"},
}

// adfsUserIDClaims follow user_id_attribute (LR37b-7, W3).
var adfsUserIDClaims = []string{samlcore.ClaimNameIdentifier, samlcore.ClaimUPN, samlcore.ClaimEmail}

// adfsProfile maps token claims to the profile. The subject is the
// user_id_attribute claim, else the subject's name identifier, else the
// nameidentifier, UPN or email claim. email_verified follows
// should_trust_email_verified_connection.
func adfsProfile(a *rules.ADFSSettings, tok *samlcore.WSFedToken) (Profile, error) {
	first := func(names ...string) string {
		for _, n := range names {
			if v := tok.Attributes[n]; len(v) > 0 && strings.TrimSpace(v[0]) != "" {
				return v[0]
			}
		}
		return ""
	}
	claims := map[string]any{}
	for field, names := range adfsDefaults {
		if v := first(names...); v != "" {
			claims[field] = v
		}
	}
	if _, ok := claims["email"]; ok {
		claims["email_verified"] = a.TrustEmailVerified
	}
	sub := ""
	if a.UserIDAttribute != "" {
		sub = first(a.UserIDAttribute)
	}
	if sub == "" {
		sub = strings.TrimSpace(tok.NameID)
	}
	if sub == "" {
		sub = first(adfsUserIDClaims...)
	}
	if strings.TrimSpace(sub) == "" || len(sub) > rules.MaxSubjectBytes {
		return Profile{}, fmt.Errorf("%w: no usable subject", ErrProfile)
	}
	return profileFromClaims(sub, claims)
}

// ADFSLogoutURL is the identity provider sign-out for a session that came
// from an adfs connection (wa=wsignout1.0 at the sign-in endpoint, wreply =
// returnTo when given), or "" when there is none (LR37b-10).
func (s *FlowService) ADFSLogoutURL(tenant *store.Tenant, conn *store.Connection, returnTo string) string {
	if conn == nil || conn.Strategy != StrategyADFS {
		return ""
	}
	cfg, err := parseConnConfig(conn)
	if err != nil || cfg.ADFS == nil || cfg.ADFS.SignInEndpoint == "" {
		return ""
	}
	u, err := url.Parse(cfg.ADFS.SignInEndpoint)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("wa", "wsignout1.0")
	if returnTo != "" {
		q.Set("wreply", returnTo)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func parseConnConfig(conn *store.Connection) (Config, error) {
	return ParseConfig(*connrules.FromConnection(conn))
}
