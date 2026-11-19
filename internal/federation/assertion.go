package federation

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"time"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// ClientAssertion signs with the currently active connection key, creating a
// key set atomically when this is its first use.
func ClientAssertion(ctx context.Context, st store.Store, w keys.Wrapper, conn *store.Connection, cfg Config, aud string, now time.Time) (string, error) {
	alg := cfg.AssertionAlg
	if alg == "" {
		alg = "RS256"
	}
	list, e := EnsureKeys(ctx, st, w, conn, "signing", alg, "zeroauthy connection", now)
	if e != nil {
		return "", e
	}
	for _, k := range list {
		if k.Use != "signing" || k.State != "current" {
			continue
		}
		key, e := OpenConnectionKey(w, k)
		if e != nil {
			return "", e
		}
		signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.SignatureAlgorithm(alg), Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{"kid": k.KID, "typ": "JWT"}})
		if e != nil {
			return "", fmt.Errorf("%w: unusable assertion key", ErrInvalidConfig)
		}
		claims := map[string]any{"iss": cfg.ClientID, "sub": cfg.ClientID, "aud": aud, "jti": randomToken(), "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		b, e := json.Marshal(claims)
		if e != nil {
			return "", e
		}
		obj, e := signer.Sign(b)
		if e != nil {
			return "", fmt.Errorf("%w: assertion signing failed", ErrInvalidConfig)
		}
		return obj.CompactSerialize()
	}
	return "", fmt.Errorf("%w: current assertion key missing", ErrInvalidConfig)
}
