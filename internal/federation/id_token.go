package federation

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func idTokenError(what string) error { return fmt.Errorf("%w: ID token %s", ErrProviderResponse, what) }

// parseIDToken accepts one RS256 signature, with keys supplied exclusively by
// the pinned JWKS. Inspect raw headers: JOSE's typed Header hides x5c metadata.
func parseIDToken(raw string) (*jose.JSONWebSignature, error) {
	obj, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(obj.Signatures) != 1 {
		return nil, idTokenError("is not a single RS256 JWS")
	}
	var serialized struct {
		Protected string                     `json:"protected"`
		Header    map[string]json.RawMessage `json:"header"`
	}
	if json.Unmarshal([]byte(obj.FullSerialize()), &serialized) != nil {
		return nil, idTokenError("headers are malformed")
	}
	protected, err := base64.RawURLEncoding.DecodeString(serialized.Protected)
	if err != nil {
		return nil, idTokenError("headers are malformed")
	}
	var header map[string]json.RawMessage
	if len(protected) > 0 && json.Unmarshal(protected, &header) != nil {
		return nil, idTokenError("headers are malformed")
	}
	for _, k := range []string{"jwk", "jku", "x5u", "x5c"} {
		if _, present := header[k]; present {
			return nil, idTokenError("names its own key")
		}
		if _, present := serialized.Header[k]; present {
			return nil, idTokenError("names its own key")
		}
	}
	return obj, nil
}

func decodeIDTokenClaims(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var c map[string]any
	if err := dec.Decode(&c); err != nil || c == nil {
		return nil, idTokenError("claims are malformed")
	}
	return c, nil
}

func (ps *Providers) exchangeTime(in ExchangeInput) time.Time {
	if !in.Now.IsZero() {
		return in.Now
	}
	return ps.now()
}

// validateIDTokenClaims is the common OIDC/Google/Microsoft claim policy.
// Issuer and Microsoft-specific tenant/key bindings remain separate policies.
func validateIDTokenClaims(in ExchangeInput, tokens TokenSet, c map[string]any, now time.Time) error {
	var aud []string
	switch v := c["aud"].(type) {
	case string:
		aud = []string{v}
	case []any:
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				return idTokenError("audience is malformed")
			}
			aud = append(aud, s)
		}
	default:
		return idTokenError("audience missing")
	}
	hasClient := false
	for _, a := range aud {
		hasClient = hasClient || a == in.Config.ClientID
	}
	azp, hasAzp := c["azp"].(string)
	if _, present := c["azp"]; present && !hasAzp {
		return idTokenError("authorized party is malformed")
	}
	if !hasClient || (len(aud) > 1 && !hasAzp) || (hasAzp && azp != in.Config.ClientID) {
		return idTokenError("audience mismatch")
	}
	exp, okExp := numericDate(c["exp"])
	iat, okIat := numericDate(c["iat"])
	if !okExp || !okIat || !now.Before(exp.Add(clockSkew)) || iat.After(now.Add(clockSkew)) {
		return idTokenError("is expired or not yet valid")
	}
	if nonce, _ := c["nonce"].(string); in.Nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(in.Nonce)) != 1 {
		return idTokenError("nonce mismatch")
	}
	if sub, _ := c["sub"].(string); ValidateSubject(sub) != nil {
		return idTokenError("subject is missing or invalid")
	}
	if v, present := c["at_hash"]; present {
		s, _ := v.(string)
		sum := sha256.Sum256([]byte(tokens.AccessToken))
		if s == "" || subtle.ConstantTimeCompare([]byte(s), []byte(base64.RawURLEncoding.EncodeToString(sum[:16]))) != 1 {
			return idTokenError("at_hash mismatch")
		}
	}
	return nil
}

func numericDate(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := n.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}
