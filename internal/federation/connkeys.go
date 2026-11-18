package federation

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/keycert"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"slices"
	"strings"
	"time"
)

const connectionKeyLabel = "connection-key/v1"

// GenerateConnectionKey seals private material before returning a store model.
func GenerateConnectionKey(w keys.Wrapper, conn *store.Connection, use, alg, subject string, now time.Time) (*store.ConnectionKey, error) {
	allowed := rules.AssertionAlgorithms
	if use == "encryption" {
		allowed = rules.EncryptionAlgorithms
	} else if use != "signing" {
		return nil, store.ErrInvalid
	}
	if !slices.Contains(allowed, alg) {
		return nil, store.ErrInvalid
	}
	var signer crypto.Signer
	var e error
	if strings.HasPrefix(alg, "ES") || strings.HasPrefix(alg, "ECDH") {
		curve := elliptic.P256()
		if alg == "ES384" {
			curve = elliptic.P384()
		}
		signer, e = ecdsa.GenerateKey(curve, rand.Reader)
	} else {
		signer, e = rsa.GenerateKey(rand.Reader, 2048)
	}
	if e != nil {
		return nil, e
	}
	der, e := keycert.CreateConnection(signer, subject, now)
	if e != nil {
		return nil, e
	}
	plain, e := x509.MarshalPKCS8PrivateKey(signer)
	if e != nil {
		return nil, e
	}
	defer clear(plain)
	k := &store.ConnectionKey{TenantID: conn.TenantID, ConnectionID: conn.ID, KID: secrets.RandomString(24), Use: use, Alg: alg, CertDER: der, CreatedAt: now.UTC()}
	k.PrivateSealed, e = keys.SealBound(w, connectionKeyLabel, []string{k.TenantID, k.ConnectionID, k.KID, k.Use, k.Alg}, plain)
	return k, e
}
func OpenConnectionKey(w keys.Wrapper, k *store.ConnectionKey) (crypto.Signer, error) {
	plain, e := keys.OpenBound(w, connectionKeyLabel, []string{k.TenantID, k.ConnectionID, k.KID, k.Use, k.Alg}, k.PrivateSealed)
	if e != nil {
		return nil, e
	}
	defer clear(plain)
	v, e := x509.ParsePKCS8PrivateKey(plain)
	if e != nil {
		return nil, errors.New("federation: invalid connection key")
	}
	signer, ok := v.(crypto.Signer)
	if !ok {
		return nil, errors.New("federation: invalid connection key type")
	}
	return signer, nil
}
func EnsureKeys(ctx context.Context, st store.Store, w keys.Wrapper, conn *store.Connection, use, alg, subject string, now time.Time) ([]*store.ConnectionKey, error) {
	repo := st.ConnectionKeys()
	list, e := repo.List(ctx, conn.TenantID, conn.ID)
	if e != nil {
		return nil, e
	}
	for _, k := range list {
		if k.Use == use {
			return list, nil
		}
	}
	current, e := GenerateConnectionKey(w, conn, use, alg, subject, now)
	if e != nil {
		return nil, e
	}
	next, e := GenerateConnectionKey(w, conn, use, alg, subject, now)
	if e != nil {
		return nil, e
	}
	current.State = "current"
	current.CurrentSince = &now
	next.State = "next"
	if e = repo.Create(ctx, conn.TenantID, conn.ID, use, current, next); e != nil && !errors.Is(e, store.ErrConflict) {
		return nil, e
	}
	return repo.List(ctx, conn.TenantID, conn.ID)
}
