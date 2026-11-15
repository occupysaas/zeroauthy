package clientcred

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Purpose selects the claim rules Verify applies.
type Purpose int

const (
	// Assertion is a client_assertion (RFC 7523): sub = iss = client, jti
	// required, lifetime at most 5 minutes, raw size at most 2048 bytes.
	Assertion Purpose = iota
	// RequestObject is a JAR request object (RFC 9101): iss = client, exp
	// required with a lifetime of at most 60 minutes, jti optional.
	RequestObject
)

const (
	leeway             = 10 * time.Second
	assertionLifetime  = 300 * time.Second
	requestObjectLife  = 3600 * time.Second
	maxAssertionBytes  = 2048
	maxIdentifierChars = 64
	maxAlgChars        = 16
)

// ErrInvalid is wrapped by every Verify failure. The message names the
// reason for server logs; it never contains the token or claim values.
var ErrInvalid = errors.New("clientcred: invalid token")

// VerifyInput is the input of Verify.
type VerifyInput struct {
	Raw         string
	ClientID    string
	Audiences   []string // accepted aud values (exact match)
	Purpose     Purpose
	Credentials []*store.ClientCredential
	Now         time.Time
	// UseJTI records a jti until exp; store.ErrConflict means replay. It is
	// called last, once the signature and claims have passed. Required
	// whenever the token carries a jti (always for an Assertion).
	UseJTI func(jti string, exp time.Time) error
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Verify checks the signature and claims of a JWT signed by one of the
// client's credentials and returns its claims.
func Verify(in VerifyInput) (map[string]any, error) {
	if in.Purpose == Assertion && len(in.Raw) > maxAssertionBytes {
		return nil, invalid("assertion longer than %d bytes", maxAssertionBytes)
	}
	if in.Raw == "" || in.ClientID == "" || len(in.Audiences) == 0 {
		return nil, invalid("missing input")
	}
	jws, err := jose.ParseSigned(in.Raw, []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.PS256})
	if err != nil {
		return nil, invalid("not a JWS with an allowed algorithm")
	}
	if len(jws.Signatures) != 1 {
		return nil, invalid("exactly one signature required")
	}
	h := jws.Signatures[0].Header
	alg := h.Algorithm
	if len(alg) > maxAlgChars {
		return nil, invalid("alg too long")
	}
	if _, ok := h.ExtraHeaders["crit"]; ok {
		return nil, invalid("crit header not supported")
	}
	if in.Purpose == RequestObject {
		if v, ok := h.ExtraHeaders[jose.HeaderType]; ok {
			typ, _ := v.(string)
			switch typ {
			case "JWT", "jwt", "oauth-authz-req+jwt":
			default:
				return nil, invalid("unsupported typ")
			}
		}
	}

	payload, err := verifySignature(jws, string(alg), h.KeyID, in)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil || claims == nil {
		return nil, invalid("payload is not a JSON object")
	}
	exp, jti, err := checkClaims(claims, in)
	if err != nil {
		return nil, err
	}
	if jti != "" {
		if in.UseJTI == nil {
			return nil, invalid("no replay guard")
		}
		if err := in.UseJTI(jti, exp.Add(leeway)); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return nil, invalid("jti already used")
			}
			return nil, invalid("jti could not be recorded")
		}
	}
	return claims, nil
}

func verifySignature(jws *jose.JSONWebSignature, alg, kid string, in VerifyInput) ([]byte, error) {
	tried := 0
	for _, c := range in.Credentials {
		if c == nil || c.Alg != alg || (kid != "" && c.KID != kid) {
			continue
		}
		if c.ExpiresAt != nil && !in.Now.Before(*c.ExpiresAt) {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(c.PublicKeyDER)
		if err != nil {
			continue
		}
		rk, ok := pub.(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < minRSABits || rk.N.BitLen() > maxRSABits {
			continue
		}
		tried++
		if payload, err := jws.Verify(rk); err == nil {
			return payload, nil
		}
	}
	if tried == 0 {
		return nil, invalid("no usable credential for alg and kid")
	}
	return nil, invalid("signature verification failed")
}

// checkClaims validates the claims and returns exp and the jti to record
// ("" when the token has none).
func checkClaims(claims map[string]any, in VerifyInput) (time.Time, string, error) {
	now := in.Now
	str := func(name string) (string, bool) {
		v, ok := claims[name].(string)
		return v, ok && v != ""
	}
	iss, ok := str("iss")
	if !ok || iss != in.ClientID || len(iss) > maxIdentifierChars {
		return time.Time{}, "", invalid("iss does not match client")
	}
	life := requestObjectLife
	if in.Purpose == Assertion {
		life = assertionLifetime
		sub, ok := str("sub")
		if !ok || sub != iss {
			return time.Time{}, "", invalid("sub does not match iss")
		}
	}
	if !audMatches(claims["aud"], in.Audiences) {
		return time.Time{}, "", invalid("aud not accepted")
	}

	expF, ok := numericDate(claims, "exp")
	if !ok {
		return time.Time{}, "", invalid("exp missing or not a number")
	}
	exp := time.Unix(expF, 0)
	if !now.Add(-leeway).Before(exp) {
		return time.Time{}, "", invalid("token expired")
	}
	if exp.Sub(now) > life+leeway {
		return time.Time{}, "", invalid("lifetime too long")
	}
	if _, present := claims["iat"]; present {
		iatF, ok := numericDate(claims, "iat")
		if !ok {
			return time.Time{}, "", invalid("iat is not a number")
		}
		iat := time.Unix(iatF, 0)
		if iat.After(now.Add(leeway)) {
			return time.Time{}, "", invalid("iat in the future")
		}
		if exp.Sub(iat) > life {
			return time.Time{}, "", invalid("lifetime too long")
		}
	} else if exp.Sub(now) > life {
		return time.Time{}, "", invalid("lifetime too long")
	}
	if _, present := claims["nbf"]; present {
		nbfF, ok := numericDate(claims, "nbf")
		if !ok {
			return time.Time{}, "", invalid("nbf is not a number")
		}
		if time.Unix(nbfF, 0).After(now.Add(leeway)) {
			return time.Time{}, "", invalid("token not yet valid")
		}
	}

	jti := ""
	if raw, present := claims["jti"]; present {
		s, isStr := raw.(string)
		if !isStr || s == "" || len(s) > maxIdentifierChars {
			return time.Time{}, "", invalid("jti malformed")
		}
		jti = s
	} else if in.Purpose == Assertion {
		return time.Time{}, "", invalid("jti missing")
	}
	return exp, jti, nil
}

func numericDate(claims map[string]any, name string) (int64, bool) {
	f, ok := claims[name].(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(math.Floor(f)), true
}

func audMatches(aud any, accepted []string) bool {
	var got []string
	switch v := aud.(type) {
	case string:
		got = []string{v}
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return false
			}
			got = append(got, s)
		}
	}
	for _, g := range got {
		for _, a := range accepted {
			if g == a && g != "" {
				return true
			}
		}
	}
	return false
}
