package federation

import (
	"context"
	"crypto/x509"
	"errors"
	"net/url"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// SAMLSPLogoutURL is a connection's SP single logout endpoint (S37-14:
// /samlp/logout?connection={name}).
func SAMLSPLogoutURL(origin, connection string) string {
	return origin + "/samlp/logout?connection=" + url.QueryEscape(connection)
}

// samlConnection loads a samlp connection and its settings by name.
func (s *FlowService) samlConnection(ctx context.Context, tenant *store.Tenant, name string) (*store.Connection, Config, error) {
	conn, err := s.Store.Connections().GetByName(ctx, tenant.ID, name)
	if errors.Is(err, store.ErrNotFound) || err == nil && conn.Strategy != StrategySAMLP {
		return nil, Config{}, store.ErrNotFound
	}
	if err != nil {
		return nil, Config{}, err
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.SAML == nil {
		return nil, Config{}, ErrConnectionUnusable
	}
	return conn, cfg, nil
}

// SAMLSPMetadata returns the SP EntityDescriptor of a samlp connection:
// entity ID, ACS, SLO and the current signing and encryption certificates
// (created lazily in the connection keys repository).
func (s *FlowService) SAMLSPMetadata(ctx context.Context, tenant *store.Tenant, origin, name string) (*etree.Element, error) {
	conn, cfg, err := s.samlConnection(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	_, sigCert, err := samlKey(ctx, s.Store, s, conn, "signing", tenant.CanonicalHost, s.now())
	if err != nil {
		return nil, err
	}
	_, encCert, err := samlKey(ctx, s.Store, s, conn, "encryption", tenant.CanonicalHost, s.now())
	if err != nil {
		return nil, err
	}
	return samlcore.BuildMetadata(samlcore.EntityDescriptor{EntityID: SAMLEntityID(tenant, conn, cfg), SP: &samlcore.SPDescriptor{
		SigningCerts: []*x509.Certificate{sigCert}, EncryptionCerts: []*x509.Certificate{encCert},
		AuthnRequestsSigned: cfg.SAML.SignRequest, WantAssertionsSigned: true,
		NameIDFormats: []string{samlcore.NameIDEmail, samlcore.NameIDUnspecified, samlcore.NameIDPersistent},
		ACS:           []samlcore.Endpoint{{Binding: samlcore.BindingPOST, Location: SAMLACSURL(origin, conn.Name)}},
		SLO:           []samlcore.Endpoint{{Binding: samlcore.BindingRedirect, Location: SAMLSPLogoutURL(origin, conn.Name)}},
	}}), nil
}

// samlSigner is the connection's SP signing key.
func (s *FlowService) samlSigner(ctx context.Context, tenant *store.Tenant, conn *store.Connection, cfg Config) (*samlcore.Signer, error) {
	key, cert, err := samlKey(ctx, s.Store, s, conn, "signing", tenant.CanonicalHost, s.now())
	if err != nil {
		return nil, err
	}
	return &samlcore.Signer{Key: key, Cert: cert, Algorithm: cfg.SAML.SignatureAlgorithm, Digest: cfg.SAML.DigestAlgorithm}, nil
}

// SAMLLogout is an SP LogoutRequest to send after a local logout.
type SAMLLogout struct {
	URL, RequestID, Connection string
}

// SAMLLogoutRequest builds the signed LogoutRequest for a session that signed
// in through a samlp connection with a signOutEndpoint and without
// disableSignout; nil when there is nothing to send.
func (s *FlowService) SAMLLogoutRequest(ctx context.Context, tenant *store.Tenant, ended *store.LoginSession) (*SAMLLogout, error) {
	if ended == nil {
		return nil, nil
	}
	var up *store.SAMLParticipant
	for i := range ended.SAMLParticipants {
		if p := &ended.SAMLParticipants[i]; p.ConnectionID != "" {
			up = p
		}
	}
	if up == nil {
		return nil, nil
	}
	conn, err := s.Store.Connections().Get(ctx, tenant.ID, up.ConnectionID)
	if err != nil || conn.Strategy != StrategySAMLP {
		return nil, nil // the connection is gone: local logout only
	}
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.SAML == nil || cfg.SAML.SignOutEndpoint == "" || cfg.SAML.DisableSignout {
		return nil, nil
	}
	signer, err := s.samlSigner(ctx, tenant, conn, cfg)
	if err != nil {
		return nil, err
	}
	now := s.now()
	lr := samlcore.LogoutRequest{ID: "_" + randomToken(), IssueInstant: now, Issuer: SAMLEntityID(tenant, conn, cfg), Destination: cfg.SAML.SignOutEndpoint,
		NameID: up.NameID, NameIDFormat: up.NameIDFormat, SessionIndex: up.SessionIndex, NotOnOrAfter: now.Add(5 * time.Minute)}
	u, err := samlcore.EncodeRedirect(cfg.SAML.SignOutEndpoint, samlcore.ParamRequest, samlcore.BuildLogoutRequest(lr), "", signer)
	if err != nil {
		return nil, err
	}
	return &SAMLLogout{URL: u, RequestID: lr.ID, Connection: conn.Name}, nil
}

// SAMLLogoutMessage is a verified logout message from a samlp IdP.
type SAMLLogoutMessage struct {
	Connection *store.Connection
	Request    *samlcore.LogoutRequest
	Response   *samlcore.LogoutResponse
}

// VerifySAMLLogout checks a logout message received at the SP SLO endpoint:
// it must be signed by the IdP's pinned certificates (HTTP-Redirect query
// signature or enveloped signature).
func (s *FlowService) VerifySAMLLogout(ctx context.Context, tenant *store.Tenant, name string, root *etree.Element, verifyRedirect func(samlcore.Trust) error) (*SAMLLogoutMessage, error) {
	conn, cfg, err := s.samlConnection(ctx, tenant, name)
	if err != nil {
		return nil, err
	}
	trust := samlcore.Trust{Thumbprints: cfg.SAML.Thumbprints, Thumbprints384: cfg.SAML.Thumbprints384, Now: s.now,
		AllowSHA1: cfg.SAML.SignatureAlgorithm == "rsa-sha1" || cfg.SAML.DigestAlgorithm == "sha1"}
	for _, der := range cfg.SAML.Certs {
		if c, err := x509.ParseCertificate(der); err == nil {
			trust.Certs = append(trust.Certs, c)
		}
	}
	if verifyRedirect != nil {
		if err := verifyRedirect(trust); err != nil {
			return nil, ErrCallbackRejected
		}
	} else if root, err = samlcore.VerifyEnveloped(root, trust); err != nil {
		return nil, ErrCallbackRejected
	}
	out := &SAMLLogoutMessage{Connection: conn}
	if out.Request, err = samlcore.ParseLogoutRequest(root); err != nil {
		if out.Response, err = samlcore.ParseLogoutResponse(root); err != nil {
			return nil, ErrCallbackRejected
		}
		out.Request = nil
	}
	return out, nil
}

// SAMLLogoutResponse answers an IdP-initiated LogoutRequest at the IdP's
// signOutEndpoint, signed with the SP key.
func (s *FlowService) SAMLLogoutResponse(ctx context.Context, tenant *store.Tenant, conn *store.Connection, inResponseTo, relay, status string) (string, error) {
	cfg, err := ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.SAML == nil || cfg.SAML.SignOutEndpoint == "" {
		return "", ErrConnectionUnusable
	}
	signer, err := s.samlSigner(ctx, tenant, conn, cfg)
	if err != nil {
		return "", err
	}
	resp := samlcore.BuildLogoutResponse(samlcore.LogoutResponse{ID: "_" + randomToken(), InResponseTo: inResponseTo, IssueInstant: s.now(),
		Issuer: SAMLEntityID(tenant, conn, cfg), Destination: cfg.SAML.SignOutEndpoint, StatusCode: status})
	return samlcore.EncodeRedirect(cfg.SAML.SignOutEndpoint, samlcore.ParamResponse, resp, relay, signer)
}
