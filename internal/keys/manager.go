package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrNoSigningKey means the tenant has no current key; call Ensure first.
var ErrNoSigningKey = errors.New("keys: tenant has no current signing key")

const rsaBits = 2048

type Manager struct {
	store store.SigningKeys
	wrap  Wrapper
	now   func() time.Time

	mu      sync.Mutex // serializes Ensure and Rotate in this process
	signers sync.Map   // "tenantID|kid" -> jose.Signer
}

func NewManager(s store.SigningKeys, w Wrapper) *Manager {
	return &Manager{store: s, wrap: w, now: time.Now}
}

// Ensure creates a current key and a next key for a tenant that has no
// keys. It does nothing if the tenant already has keys.
func (m *Manager) Ensure(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	if len(ks) > 0 {
		return nil
	}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext} {
		k, err := m.generate(tenantID, status)
		if err != nil {
			return err
		}
		if err := m.store.Create(ctx, k); err != nil {
			return err
		}
	}
	return nil
}

// Rotate promotes next to current and publishes a fresh next key.
func (m *Manager) Rotate(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := m.generate(tenantID, store.KeyNext)
	if err != nil {
		return err
	}
	return m.store.Rotate(ctx, tenantID, next)
}

// Sign serializes claims as a JWT signed with the tenant's current key.
func (m *Manager) Sign(ctx context.Context, tenantID string, claims any) (string, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return "", err
	}
	for _, k := range ks {
		if k.Status == store.KeyCurrent {
			signer, err := m.signer(k)
			if err != nil {
				return "", err
			}
			return jwt.Signed(signer).Claims(claims).Serialize()
		}
	}
	return "", ErrNoSigningKey
}

// JWKS returns the tenant's published keys: current, next, previous.
func (m *Manager) JWKS(ctx context.Context, tenantID string) (jose.JSONWebKeySet, error) {
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext, store.KeyPrevious} {
		for _, k := range ks {
			if k.Status != status {
				continue
			}
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(k.PublicJWK, &jwk); err != nil {
				return jose.JSONWebKeySet{}, fmt.Errorf("keys: stored JWK %s: %w", k.KID, err)
			}
			set.Keys = append(set.Keys, jwk)
		}
	}
	return set, nil
}

func (m *Manager) generate(tenantID string, status store.KeyStatus) (*store.SigningKey, error) {
	priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}
	pub := jose.JSONWebKey{Key: &priv.PublicKey, Algorithm: string(jose.RS256), Use: "sig"}
	thumb, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	pub.KeyID = base64.RawURLEncoding.EncodeToString(thumb) // RFC 7638 thumbprint
	pubJSON, err := pub.MarshalJSON()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	sealed, err := seal(m.wrap, der, aad(tenantID, pub.KeyID))
	if err != nil {
		return nil, err
	}
	return &store.SigningKey{
		TenantID:   tenantID,
		KID:        pub.KeyID,
		Alg:        string(jose.RS256),
		Status:     status,
		PrivateKey: sealed,
		PublicJWK:  pubJSON,
		CreatedAt:  m.now().UTC(),
	}, nil
}

func (m *Manager) signer(k *store.SigningKey) (jose.Signer, error) {
	cacheKey := k.TenantID + "|" + k.KID
	if s, ok := m.signers.Load(cacheKey); ok {
		return s.(jose.Signer), nil
	}
	der, err := unseal(m.wrap, k.PrivateKey, aad(k.TenantID, k.KID))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keys: %s is not an RSA key", k.KID)
	}
	s, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: rsaKey},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.KID),
	)
	if err != nil {
		return nil, err
	}
	m.signers.Store(cacheKey, s)
	return s, nil
}

// aad binds ciphertext to its tenant and key ID so a sealed key cannot be
// moved to another record.
func aad(tenantID, kid string) []byte { return []byte(tenantID + "|" + kid) }
