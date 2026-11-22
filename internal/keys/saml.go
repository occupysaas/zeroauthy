package keys

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// SAMLSigner returns the tenant's current signing key as a crypto.Signer with
// its certificate, for XML signatures (Plan 37a). The private key never
// leaves this process and is not cached beyond the call.
func (m *Manager) SAMLSigner(ctx context.Context, tenantID string) (crypto.Signer, *x509.Certificate, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	for _, k := range ks {
		if k.TenantID != tenantID || k.Status != store.KeyCurrent {
			continue
		}
		if len(k.CertificateDER) == 0 {
			return nil, nil, errors.New("keys: current key has no certificate")
		}
		cert, err := x509.ParseCertificate(k.CertificateDER)
		if err != nil {
			return nil, nil, err
		}
		der, err := unseal(m.wrap, k.PrivateKey, aad(k.TenantID, k.KID))
		if err != nil {
			return nil, nil, err
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok || !key.PublicKey.Equal(cert.PublicKey) {
			return nil, nil, errors.New("keys: current key and certificate do not match")
		}
		return key, cert, nil
	}
	return nil, nil, ErrNoSigningKey
}

// SAMLCertificates returns the certificates SAML metadata publishes: the
// current key first, then the next key when present.
func (m *Manager) SAMLCertificates(ctx context.Context, tenantID string) ([]*x509.Certificate, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, want := range []store.KeyStatus{store.KeyCurrent, store.KeyNext} {
		for _, k := range ks {
			if k.TenantID != tenantID || k.Status != want || len(k.CertificateDER) == 0 {
				continue
			}
			cert, err := x509.ParseCertificate(k.CertificateDER)
			if err != nil {
				return nil, err
			}
			out = append(out, cert)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoSigningKey
	}
	return out, nil
}
