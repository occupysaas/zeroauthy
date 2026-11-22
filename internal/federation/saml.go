package federation

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"net/url"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// StrategySAMLP is the SAML service-provider connection strategy (Plan 37a).
const StrategySAMLP = rules.SAMLP

// samlSkew is LR37a-3's clock skew.
const samlSkew = 2 * time.Minute

// ErrSAMLResponse is a SAML response that failed validation. Details stay in
// the operator log as error classes only.
var ErrSAMLResponse = errors.New("federation: SAML response refused")

// SAMLACSURL is a connection's assertion consumer service (Auth0's form).
func SAMLACSURL(origin, connection string) string {
	return strings.TrimSuffix(origin, "/") + CallbackPath + "?connection=" + url.QueryEscape(connection)
}

// SAMLEntityID is the SP entity ID: options.entityId or
// urn:auth0:{tenant}:{connection} (documented default).
func SAMLEntityID(tenant *store.Tenant, conn *store.Connection, cfg Config) string {
	if cfg.SAML != nil && cfg.SAML.EntityID != "" {
		return cfg.SAML.EntityID
	}
	return "urn:auth0:" + tenant.Name + ":" + conn.Name
}

// samlRequestID binds the AuthnRequest ID to the attempt's sealed nonce.
func samlRequestID(nonce string) string { return "_" + nonce }

// samlKey returns the connection's current RSA SP key and certificate for
// use ("signing" or "encryption"), creating the pair lazily.
func samlKey(ctx context.Context, st store.Store, s *FlowService, conn *store.Connection, use, subject string, now time.Time) (*rsa.PrivateKey, *x509.Certificate, error) {
	alg := "RS256"
	if use == "encryption" {
		alg = "RSA-OAEP-256"
	}
	list, err := EnsureKeys(ctx, st, s.Wrapper, conn, use, alg, subject, now)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range list {
		if k.Use != use || k.State != "current" {
			continue
		}
		signer, err := OpenConnectionKey(s.Wrapper, k)
		if err != nil {
			return nil, nil, err
		}
		key, ok := signer.(*rsa.PrivateKey)
		cert, cerr := x509.ParseCertificate(k.CertDER)
		if !ok || cerr != nil {
			return nil, nil, ErrConnectionUnusable
		}
		return key, cert, nil
	}
	return nil, nil, ErrConnectionUnusable
}

// samlAuthnRequest builds the AuthnRequest for an attempt: the URL to
// redirect to (HTTP-Redirect) or the form to post (HTTP-POST).
func (s *FlowService) samlAuthnRequest(ctx context.Context, tenant *store.Tenant, conn *store.Connection, cfg Config, acs, state, nonce string) (string, url.Values, error) {
	sc := cfg.SAML
	dest := sc.Destination
	if dest == "" {
		dest = sc.SignInEndpoint
	}
	req, err := samlcore.BuildAuthnRequest(samlcore.AuthnRequest{ID: samlRequestID(nonce), IssueInstant: s.now(), Issuer: SAMLEntityID(tenant, conn, cfg),
		Destination: dest, ACSURL: acs, ProtocolBinding: samlcore.BindingPOST}, sc.RequestTemplate)
	if err != nil {
		return "", nil, ErrConnectionUnusable
	}
	var signer *samlcore.Signer
	if sc.SignRequest {
		key, cert, err := samlKey(ctx, s.Store, s, conn, "signing", tenant.CanonicalHost, s.now())
		if err != nil {
			return "", nil, err
		}
		signer = &samlcore.Signer{Key: key, Cert: cert, Algorithm: sc.SignatureAlgorithm, Digest: sc.DigestAlgorithm}
	}
	if sc.ProtocolBinding == samlcore.BindingPOST {
		if signer != nil {
			if req, err = signer.SignEnveloped(req); err != nil {
				return "", nil, err
			}
		}
		return sc.SignInEndpoint, url.Values{samlcore.ParamRequest: {samlcore.EncodePOST(req)}, "RelayState": {state}}, nil
	}
	u, err := samlcore.EncodeRedirect(sc.SignInEndpoint, samlcore.ParamRequest, req, state, signer)
	return u, nil, err
}

// samlAssertion is a validated SAML login.
type samlAssertion struct {
	Result    ProviderResult
	ID        string
	ExpiresAt time.Time
}

// samlValidate verifies a posted SAMLResponse for conn. inResponseTo is the
// attempt's request ID, or "" for an IdP-initiated login (allowed only when
// the connection enables it).
func (s *FlowService) samlValidate(ctx context.Context, tenant *store.Tenant, conn *store.Connection, cfg Config, origin, inResponseTo, raw string) (*samlAssertion, error) {
	sc := cfg.SAML
	if sc == nil {
		return nil, ErrConnectionUnusable
	}
	doc, err := samlcore.DecodePOST(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed", ErrSAMLResponse)
	}
	trust := samlcore.Trust{Thumbprints: sc.Thumbprints, Thumbprints384: sc.Thumbprints384, Now: s.now,
		AllowSHA1: sc.SignatureAlgorithm == "rsa-sha1" || sc.DigestAlgorithm == "sha1"}
	for _, der := range sc.Certs {
		if c, err := x509.ParseCertificate(der); err == nil {
			trust.Certs = append(trust.Certs, c)
		}
	}
	decrypt := func(enc *etree.Element) (*etree.Element, error) {
		key, _, err := samlKey(ctx, s.Store, s, conn, "encryption", tenant.CanonicalHost, s.now())
		if err != nil {
			return nil, err
		}
		return samlcore.DecryptAssertion(enc, key, samlcore.Decryption{AllowRSA15: sc.AllowRSA15})
	}
	v, err := samlcore.VerifyResponse(doc, trust, decrypt)
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrSAMLResponse)
	}
	env, err := samlcore.ParseResponseEnvelope(v.Response)
	if err != nil || env.StatusCode != samlcore.StatusSuccess {
		return nil, ErrProviderDenied
	}
	a, err := samlcore.ParseAssertion(v.Assertion)
	if err != nil {
		return nil, fmt.Errorf("%w: assertion", ErrSAMLResponse)
	}
	acs := SAMLACSURL(origin, conn.Name)
	recipient := sc.Recipient
	if recipient == "" {
		recipient = acs
	}
	if env.Destination != "" && env.Destination != acs && env.Destination != recipient {
		return nil, fmt.Errorf("%w: destination", ErrSAMLResponse)
	}
	if env.InResponseTo != "" && env.InResponseTo != inResponseTo {
		return nil, fmt.Errorf("%w: request", ErrSAMLResponse)
	}
	if sc.IdPEntityID != "" && a.Issuer != sc.IdPEntityID {
		return nil, fmt.Errorf("%w: issuer", ErrSAMLResponse)
	}
	if err := a.Check(samlcore.Expect{Now: s.now(), Skew: samlSkew, Audience: SAMLEntityID(tenant, conn, cfg), Recipient: recipient,
		InResponseTo: inResponseTo, AllowUnsolicited: inResponseTo == "" && sc.IdPInitiated.Enabled}); err != nil {
		return nil, fmt.Errorf("%w: conditions", ErrSAMLResponse)
	}
	profile, err := samlProfile(sc, a)
	if err != nil {
		return nil, err
	}
	exp := a.NotOnOrAfter
	if !a.ConfirmationNotOnOrAfter.IsZero() && a.ConfirmationNotOnOrAfter.After(exp) {
		exp = a.ConfirmationNotOnOrAfter
	}
	return &samlAssertion{Result: ProviderResult{Profile: profile}, ID: a.ID, ExpiresAt: exp.Add(samlSkew)}, nil
}

// samlDefaults are the attribute names tried for each profile field when
// fieldsMap does not name one.
var samlDefaults = map[string][]string{
	"email":       {samlcore.ClaimEmail, "email", "mail", "urn:oid:0.9.2342.19200300.100.1.3"},
	"name":        {samlcore.ClaimName, "name", "displayName"},
	"given_name":  {samlcore.ClaimGivenName, "given_name", "givenName", "firstName"},
	"family_name": {samlcore.ClaimSurname, "family_name", "sn", "lastName"},
	"nickname":    {"nickname"},
	"picture":     {"picture"},
}

// samlProfile maps assertion attributes to the profile: fieldsMap names
// first, then the defaults. The subject is user_id_attribute or the NameID.
func samlProfile(sc *rules.SAMLSettings, a *samlcore.Assertion) (Profile, error) {
	first := func(names []string) string {
		for _, n := range names {
			if v := a.Attributes[n]; len(v) > 0 && v[0] != "" {
				return v[0]
			}
		}
		return ""
	}
	claims := map[string]any{}
	for field, names := range samlDefaults {
		if mapped, ok := sc.FieldsMap[field]; ok {
			names = mapped
		}
		if v := first(names); v != "" {
			claims[field] = v
		}
	}
	for field, names := range sc.FieldsMap {
		if _, done := samlDefaults[field]; done {
			continue
		}
		if field == "email_verified" {
			if v := first(names); v == "true" || v == "1" {
				claims["email_verified"] = true
			}
		}
	}
	sub := a.NameID
	if sc.UserIDAttribute != "" {
		sub = first([]string{sc.UserIDAttribute})
	}
	if strings.TrimSpace(sub) == "" || len(sub) > rules.MaxSubjectBytes {
		return Profile{}, fmt.Errorf("%w: no usable subject", ErrProfile)
	}
	return profileFromClaims(sub, claims)
}

// useSAMLAssertion consumes the assertion ID inside the commit transaction.
// A replay is a rejected callback, not a store conflict (which Complete
// retries).
func useSAMLAssertion(ctx context.Context, tx store.Store, conn *store.Connection, a *samlAssertion, now time.Time) error {
	repo, ok := tx.(store.SAMLReplayStore)
	if !ok {
		return ErrConnectionUnusable
	}
	err := repo.UseSAMLAssertion(ctx, conn.TenantID, conn.ID, a.ID, a.ExpiresAt, now)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalid) {
		return fmt.Errorf("%w: assertion already used", ErrCallbackRejected)
	}
	return err
}

// SAMLUnsolicited is a committed IdP-initiated SAML login (Plan 37a): the
// user is resolved; the caller starts the session and continues to Next.
type SAMLUnsolicited struct {
	User       *store.User
	Connection *store.Connection
	ClientID   string
	Protocol   string // "oidc" or "samlp"
	Query      url.Values
}

// CompleteSAMLUnsolicited validates an unsolicited response posted to the
// ACS of connection, only when the connection enables IdP-initiated login
// and its configured application may use it.
func (s *FlowService) CompleteSAMLUnsolicited(ctx context.Context, tenant *store.Tenant, origin, connection, raw string) (*SAMLUnsolicited, error) {
	ctx = logscrub.WithCredentials(logscrub.WithValues(ctx, raw), raw)
	conn, err := s.Store.Connections().GetByName(ctx, tenant.ID, connection)
	if err != nil || conn.Strategy != StrategySAMLP {
		return nil, ErrCallbackRejected
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.SAML == nil || !cfg.AuthenticationActive {
		return nil, ErrConnectionUnusable
	}
	ip := cfg.SAML.IdPInitiated
	if !ip.Enabled || ip.ClientID == "" {
		return nil, fmt.Errorf("%w: IdP-initiated login is disabled", ErrCallbackRejected)
	}
	client, err := s.Store.Clients().Get(ctx, tenant.ID, ip.ClientID)
	if err != nil || !access.ConnectionUsable(client, conn) {
		return nil, ErrConnectionUnusable
	}
	assertion, err := s.samlValidate(ctx, tenant, conn, cfg, origin, "", raw)
	if err != nil {
		return nil, err
	}
	var user *store.User
	err = s.Store.WithTx(ctx, func(tx store.Store) error {
		if err := useSAMLAssertion(ctx, tx, conn, assertion, s.now()); err != nil {
			return err
		}
		var e error
		user, _, e = s.resolveIdentity(ctx, tx, conn, assertion.Result, nil)
		return e
	})
	if err != nil {
		return nil, err
	}
	q, _ := url.ParseQuery(ip.AuthorizeQuery)
	q.Set("client_id", client.ClientID)
	return &SAMLUnsolicited{User: user, Connection: conn, ClientID: client.ClientID, Protocol: ip.Protocol, Query: q}, nil
}
