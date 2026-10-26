package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// PublishChallengeForTest stores a live challenge record directly.
func (m *Manager) PublishChallengeForTest(ctx context.Context, typ, identifier, token, keyAuth string, expires time.Time) error {
	row := &store.TLSAsset{Kind: store.TLSAssetChallenge, ExpiresAt: expires,
		PublicData: store.TLSPublicData{Version: PublicDataVersion, ChallengeType: typ, Identifier: identifier, Token: token, KeyAuthorization: keyAuth}}
	if typ == "http-01" {
		row.Key = challengeKey(typ, token)
	} else {
		row.Key = challengeKey(typ, identifier)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: token}, DNSNames: []string{identifier},
			NotBefore: expires.Add(-2 * time.Hour), NotAfter: expires}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return err
		}
		if err := m.sealChallengeCert(row, [][]byte{der}, key); err != nil {
			return err
		}
	}
	return m.st.TLSAssets().Put(ctx, row, 0)
}
