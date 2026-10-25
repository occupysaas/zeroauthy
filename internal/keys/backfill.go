package keys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keycert"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// BackfillCertificates adds a stable public certificate to legacy rows without
// changing their key identity or lifecycle state.
func (m *Manager) BackfillCertificates(ctx context.Context, tenantID string) error {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	return m.backfill(ctx, tenantID, ks)
}

func (m *Manager) backfill(ctx context.Context, tenantID string, ks []*store.SigningKey) error {
	for _, k := range ks {
		if len(k.CertificateDER) != 0 {
			continue
		}
		plain, err := unseal(m.wrap, k.PrivateKey, aad(tenantID, k.KID))
		if err != nil {
			return fmt.Errorf("keys: backfill %s: %w", k.KID, err)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(plain)
		if err != nil {
			return fmt.Errorf("keys: backfill %s: %w", k.KID, err)
		}
		priv, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("keys: backfill %s: not RSA", k.KID)
		}
		var jwk jose.JSONWebKey
		if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
			return fmt.Errorf("keys: backfill %s: %w", k.KID, err)
		}
		pub, ok := jwk.Key.(*rsa.PublicKey)
		if !ok || pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
			return fmt.Errorf("keys: backfill %s: private/public key mismatch", k.KID)
		}
		der, err := keycert.Create(priv, k.CreatedAt)
		if err != nil {
			return fmt.Errorf("keys: backfill %s: %w", k.KID, err)
		}
		updated, err := m.store.SetCertificateIfAbsent(ctx, tenantID, k.KID, der)
		if err != nil {
			return fmt.Errorf("keys: backfill %s: %w", k.KID, err)
		}
		if updated == nil || !equalCertificateIdentity(updated.CertificateDER, priv) {
			return fmt.Errorf("keys: backfill %s: certificate CAS returned mismatched identity", k.KID)
		}
	}
	return nil
}

func equalCertificateIdentity(der []byte, priv *rsa.PrivateKey) bool {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	return ok && pub.N.Cmp(priv.N) == 0 && pub.E == priv.E
}
