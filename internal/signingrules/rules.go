package signingrules

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keycert"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ManagedKey is the public Management API projection of a managed key.
type ManagedKey struct {
	KID          string     `json:"kid"`
	Alg          string     `json:"alg"`
	Cert         string     `json:"cert,omitempty"`
	Fingerprint  string     `json:"fingerprint,omitempty"`
	Thumbprint   string     `json:"thumbprint,omitempty"`
	PKCS7        string     `json:"pkcs7,omitempty"`
	Current      bool       `json:"current"`
	Next         bool       `json:"next"`
	Previous     bool       `json:"previous"`
	Revoked      bool       `json:"revoked"`
	CurrentSince *time.Time `json:"current_since,omitempty"`
	CurrentUntil *time.Time `json:"current_until,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// Project returns the public contract for a managed key and never copies
// encrypted or plaintext private material into the projection.
func Project(k *store.SigningKey) (ManagedKey, error) {
	if k == nil || k.KID == "" {
		return ManagedKey{}, errors.New("signingrules: missing managed key")
	}
	var out ManagedKey
	out.KID, out.Alg = k.KID, k.Alg
	out.Current = k.Status == store.KeyCurrent
	out.Next = k.Status == store.KeyNext
	out.Previous = k.Status == store.KeyPrevious
	out.Revoked = k.Status == store.KeyRevoked
	out.CurrentSince = cloneTime(k.CurrentSince)
	out.CurrentUntil = cloneTime(k.CurrentUntil)
	out.RevokedAt = cloneTime(k.RevokedAt)
	if len(k.CertificateDER) != 0 {
		cert, err := keycert.Describe(k.CertificateDER)
		if err != nil {
			return ManagedKey{}, fmt.Errorf("signingrules: invalid certificate: %w", err)
		}
		out.Cert, out.Fingerprint, out.Thumbprint, out.PKCS7 = cert.Cert, cert.Fingerprint, cert.Thumbprint, cert.PKCS7
	}
	return out, nil
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

// ParseCustom validates a custom public JWKS and returns compact JSON while
// preserving the caller's member and key order.
func ParseCustom(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, errors.New("signingrules: invalid JWKS JSON")
	}
	if err := rejectDuplicateJSONMembers(raw); err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, errors.New("signingrules: JWKS must be an object")
	}
	if len(root) != 1 {
		return nil, errors.New("signingrules: JWKS must contain only keys")
	}
	keysRaw, ok := root["keys"]
	if !ok {
		return nil, errors.New("signingrules: missing keys")
	}
	var keys []json.RawMessage
	if err := json.Unmarshal(keysRaw, &keys); err != nil || len(keys) < 1 || len(keys) > 10 {
		return nil, errors.New("signingrules: keys must contain between 1 and 10 entries")
	}
	ids := make(map[string]struct{}, len(keys))
	for i, keyRaw := range keys {
		id, err := validateCustomKey(keyRaw)
		if err != nil {
			return nil, fmt.Errorf("signingrules: key %d: %w", i, err)
		}
		if _, exists := ids[id]; exists {
			return nil, errors.New("signingrules: duplicate key ID")
		}
		ids[id] = struct{}{}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, errors.New("signingrules: invalid JWKS JSON")
	}
	return append(json.RawMessage(nil), compact.Bytes()...), nil
}

// KeyIDs returns IDs from a validated custom set, preserving order.
func KeyIDs(raw json.RawMessage) ([]string, error) {
	validated, err := ParseCustom(raw)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(validated, &set); err != nil {
		return nil, err
	}
	ids := make([]string, len(set.Keys))
	for i := range set.Keys {
		ids[i] = set.Keys[i].KID
	}
	return ids, nil
}

func validateCustomKey(raw json.RawMessage) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", errors.New("key must be an object")
	}
	allowed := map[string]bool{"kty": true, "kid": true, "use": true, "key_ops": true, "alg": true, "n": true, "e": true, "crv": true, "x": true, "y": true, "x5c": true, "x5t": true, "x5t#S256": true, "x5u": true}
	for name := range m {
		if !allowed[name] {
			return "", fmt.Errorf("unknown member %q", name)
		}
	}
	if _, ok := m["x5u"]; ok {
		return "", errors.New("x5u is not accepted")
	}
	for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		if _, ok := m[name]; ok {
			return "", errors.New("private or symmetric key material is not accepted")
		}
	}
	var key struct {
		KTY    string   `json:"kty"`
		KID    string   `json:"kid"`
		Use    string   `json:"use"`
		Alg    string   `json:"alg"`
		KeyOps []string `json:"key_ops"`
		N      string   `json:"n"`
		E      string   `json:"e"`
		Crv    string   `json:"crv"`
		X      string   `json:"x"`
		Y      string   `json:"y"`
		X5C    []string `json:"x5c"`
	}
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", err
	}
	if strings.TrimSpace(key.KID) == "" || key.KID != strings.TrimSpace(key.KID) {
		return "", errors.New("kid is required")
	}
	if key.Use != "" && key.Use != "sig" {
		return "", errors.New("use must be sig")
	}
	if len(key.KeyOps) != 0 && (len(key.KeyOps) != 1 || key.KeyOps[0] != "verify") {
		return "", errors.New("key_ops must be verify only")
	}
	switch key.KTY {
	case "RSA":
		if key.Alg != "RS256" {
			return "", errors.New("RSA keys must use RS256")
		}
		n, errN := decodeURLInt(key.N)
		e, errE := decodeURLInt(key.E)
		if errN != nil || errE != nil || n.Sign() <= 0 || e.Sign() <= 0 || !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 {
			return "", errors.New("invalid RSA public parameters")
		}
		if _, ok := m["crv"]; ok {
			return "", errors.New("RSA key has EC member")
		}
	case "EC":
		if key.Alg != "ES256" || key.Crv != "P-256" {
			return "", errors.New("EC keys must use P-256 and ES256")
		}
		x, errX := decodeURLInt(key.X)
		y, errY := decodeURLInt(key.Y)
		curve := elliptic.P256()
		if errX != nil || errY != nil || !curve.IsOnCurve(x, y) {
			return "", errors.New("invalid EC public parameters")
		}
	default:
		return "", errors.New("only RSA and EC public keys are accepted")
	}
	if len(key.X5C) > 0 {
		if len(key.X5C) > 5 {
			return "", errors.New("x5c chain exceeds five certificates")
		}
		certs := make([]*x509.Certificate, len(key.X5C))
		for i, encoded := range key.X5C {
			if len(encoded) > 48*1024 {
				return "", errors.New("x5c certificate is too large")
			}
			certDER, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return "", errors.New("invalid x5c certificate")
			}
			certs[i], err = x509.ParseCertificate(certDER)
			if err != nil {
				return "", errors.New("invalid x5c certificate")
			}
		}
		switch pub := certs[0].PublicKey.(type) {
		case *rsa.PublicKey:
			n, _ := decodeURLInt(key.N)
			e, _ := decodeURLInt(key.E)
			if key.KTY != "RSA" || pub.N.Cmp(n) != 0 || big.NewInt(int64(pub.E)).Cmp(e) != 0 {
				return "", errors.New("x5c certificate does not match key")
			}
		case *ecdsa.PublicKey:
			x, _ := decodeURLInt(key.X)
			y, _ := decodeURLInt(key.Y)
			if key.KTY != "EC" || pub.Curve.Params().Name != "P-256" || pub.X.Cmp(x) != 0 || pub.Y.Cmp(y) != 0 {
				return "", errors.New("x5c certificate does not match key")
			}
		default:
			return "", errors.New("x5c certificate type is unsupported")
		}
	}
	return key.KID, nil
}

func decodeURLInt(s string) (*big.Int, error) {
	if s == "" {
		return nil, errors.New("missing integer")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("invalid base64url integer")
	}
	return new(big.Int).SetBytes(b), nil
}

// rejectDuplicateJSONMembers walks JSON tokens before struct decoding can
// discard duplicate members.
func rejectDuplicateJSONMembers(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walkJSONValue(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("signingrules: trailing JSON data")
	}
	return nil
}

func walkJSONValue(d *json.Decoder) error {
	tok, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			nameToken, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("signingrules: invalid JSON object key")
			}
			if seen[name] {
				return fmt.Errorf("signingrules: duplicate JSON member %q", name)
			}
			seen[name] = true
			if err := walkJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case '[':
		for d.More() {
			if err := walkJSONValue(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	default:
		return errors.New("signingrules: invalid JSON delimiter")
	}
}
