package keys

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/zeroauthy/zeroauthy/internal/keycert"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ErrNoSigningKey means the tenant has no current key; call Ensure first.
var ErrNoSigningKey = errors.New("keys: tenant has no current signing key")

// ErrInvalidToken means a token is malformed, uses another algorithm, or
// is not signed by one of the tenant's published keys.
var ErrInvalidToken = errors.New("keys: invalid token")

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

// Ensure makes sure the tenant has one current and one next key, creating
// whichever is missing. Concurrent callers (other processes) may race; the
// store rejects a second current/next key with ErrConflict, which Ensure
// treats as "someone else created it".
func (m *Manager) Ensure(ctx context.Context, tenantID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ks, err := m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := m.backfill(ctx, tenantID, ks); err != nil {
		return err
	}
	ks, err = m.store.List(ctx, tenantID)
	if err != nil {
		return err
	}
	have := map[store.KeyStatus]bool{}
	for _, k := range ks {
		have[k.Status] = true
	}
	for _, status := range []store.KeyStatus{store.KeyCurrent, store.KeyNext} {
		if have[status] {
			continue
		}
		at := m.now().UTC()
		k, err := m.generateAt(tenantID, status, at)
		if err != nil {
			return err
		}
		if status == store.KeyCurrent {
			k.CurrentSince = &at
		}
		if err := m.store.Create(ctx, k); err != nil && !errors.Is(err, store.ErrConflict) {
			return err
		}
	}
	return nil
}

// Rotate promotes next to current and publishes a fresh next key.
func (m *Manager) Rotate(ctx context.Context, tenantID string) error {
	_, err := m.RotateWithResult(ctx, tenantID)
	return err
}

func (m *Manager) RotateWithResult(ctx context.Context, tenantID string) (*store.SigningKeyRotation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	at := m.now().UTC()
	before, err := m.store.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var retired string
	for _, k := range before {
		if k.Status == store.KeyCurrent {
			retired = k.KID
			break
		}
	}
	next, err := m.generateAt(tenantID, store.KeyNext, at)
	if err != nil {
		return nil, err
	}
	result, err := m.store.RotateWithResult(ctx, tenantID, next, at)
	if err != nil {
		return nil, err
	}
	if retired != "" {
		m.signers.Delete(tenantID + "|" + retired)
	}
	return result, nil
}

func (m *Manager) Revoke(ctx context.Context, tenantID, kid string) (*store.SigningKey, error) {
	k, err := m.store.Revoke(ctx, tenantID, kid, m.now().UTC())
	if err != nil {
		return nil, err
	}
	m.signers.Delete(tenantID + "|" + kid)
	return k, nil
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
	return m.VerificationKeys(ctx, tenantID)
}

func (m *Manager) generate(tenantID string, status store.KeyStatus) (*store.SigningKey, error) {
	return m.generateAt(tenantID, status, m.now().UTC())
}

func (m *Manager) generateAt(tenantID string, status store.KeyStatus, at time.Time) (*store.SigningKey, error) {
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
	at = at.UTC()
	certDER, err := keycert.Create(priv, at)
	if err != nil {
		return nil, err
	}
	now := at
	var since *time.Time
	if status == store.KeyCurrent {
		since = &now
	}
	return &store.SigningKey{
		TenantID:       tenantID,
		KID:            pub.KeyID,
		Alg:            string(jose.RS256),
		Status:         status,
		PrivateKey:     sealed,
		PublicJWK:      pubJSON,
		CreatedAt:      at,
		CertificateDER: certDER,
		CurrentSince:   since,
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

// Verify checks raw's signature against the tenant's published keys
// (current, next, previous) and decodes its claims into dst. It does not
// validate time or audience claims.
func (m *Manager) Verify(ctx context.Context, tenantID, raw string, dst ...any) error {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(tok.Headers) != 1 {
		return ErrInvalidToken
	}
	set, err := m.JWKS(ctx, tenantID)
	if err != nil {
		return err
	}
	matches := set.Key(tok.Headers[0].KeyID)
	if len(matches) != 1 {
		return ErrInvalidToken
	}
	if err := tok.Claims(matches[0].Key, dst...); err != nil {
		return ErrInvalidToken
	}
	return nil
}
