package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	appleIssuer         = "https://appleid.apple.com"
	appleSecretLifetime = 5 * time.Minute
	appleSecretCacheTTL = 4 * time.Minute
)

// appleClientSecret signs Apple's client_secret with credentials already
// validated by the connection rules. sub is the Services ID for web exchanges
// or the bundle ID for native exchanges. No input or JOSE error is returned in
// an error message: callers may safely report the configuration error.
// Protocol: https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
// The five-minute lifetime is LR39a-7 in the Plan 39a design.
func appleClientSecret(teamID, kid, sub string, key *ecdsa.PrivateKey, now time.Time) (string, error) {
	if !validAppleSigningKey(key) {
		return "", fmt.Errorf("%w: Apple signing key must be P-256", ErrInvalidConfig)
	}
	if teamID == "" || kid == "" || sub == "" {
		return "", fmt.Errorf("%w: Apple signing identifiers are required", ErrInvalidConfig)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		return "", fmt.Errorf("%w: Apple client secret signer", ErrInvalidConfig)
	}
	claims := struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		IssuedAt int64  `json:"iat"`
		Expires  int64  `json:"exp"`
	}{teamID, sub, appleIssuer, now.Unix(), now.Add(appleSecretLifetime).Unix()}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%w: Apple client secret claims", ErrInvalidConfig)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("%w: Apple client secret signature", ErrInvalidConfig)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("%w: Apple client secret serialization", ErrInvalidConfig)
	}
	return token, nil
}

func validAppleSigningKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.D != nil &&
		key.D.Sign() > 0 && key.D.Cmp(elliptic.P256().Params().N) < 0 &&
		key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y)
}

type appleSecretEntry struct {
	token    string
	issuedAt time.Time
}

// appleClientSecret caches only the signed secret, never the private key.
// CacheKey's tenant, connection and revision isolate configuration changes;
// the subject isolates web and native credentials. The cache is bounded by
// maxCacheEntries like the existing federation caches. Serializing a cache
// miss also lets a burst reuse one signature.
func (ps *Providers) appleClientSecret(cache CacheKey, teamID, kid, sub string, key *ecdsa.PrivateKey) (string, error) {
	if !validAppleSigningKey(key) {
		return "", fmt.Errorf("%w: Apple signing key must be P-256", ErrInvalidConfig)
	}
	ck := cache.with("apple-client-secret", teamID, kid, sub)
	ps.appleSecretMu.Lock()
	defer ps.appleSecretMu.Unlock()
	now := ps.now()
	if entry, ok := ps.appleSecrets.get(ck); ok && !now.Before(entry.issuedAt) {
		return entry.token, nil
	}
	token, err := appleClientSecret(teamID, kid, sub, key, now)
	if err != nil {
		return "", err
	}
	ps.appleSecrets.put(ck, appleSecretEntry{token: token, issuedAt: now})
	return token, nil
}
