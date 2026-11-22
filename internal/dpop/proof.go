// Package dpop validates bounded RFC 9449 proofs without fetching keys.
package dpop

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type NonceDomain string

const (
	AuthorizationServer NonceDomain = "authorization-server"
	UserInfo            NonceDomain = "userinfo"
)

type Service struct {
	Store   store.Store
	Wrapper keys.Wrapper
	Now     func() time.Time
}
type Proof struct{ JKT, Nonce string }
type Error struct {
	Code, Nonce string
	Internal    bool
}

func (e *Error) Error() string { return e.Code }
func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func invalid() *Error  { return &Error{Code: "invalid_dpop_proof"} }
func internal() *Error { return &Error{Code: "server_error", Internal: true} }

// Verify uses only the resolved origin. Raw forwarded headers are never trusted.
func (s *Service) Verify(ctx context.Context, r *http.Request, res tenant.Resolved, domain NonceDomain, requireNonce bool, accessToken, expectedJKT string) (*Proof, *Error) {
	if s == nil || s.Store == nil || res.Tenant == nil {
		return nil, internal()
	}
	values := r.Header.Values("DPoP")
	if len(values) != 1 || len(values[0]) > 16384 || strings.Contains(values[0], ",") {
		return nil, invalid()
	}
	raw := values[0]
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, invalid()
	}
	hb, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil || !uniqueJSON(hb) {
		return nil, invalid()
	}
	pb, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil || !uniqueJSON(pb) {
		return nil, invalid()
	}
	var header map[string]json.RawMessage
	if json.Unmarshal(hb, &header) != nil {
		return nil, invalid()
	}
	typ, ok := jsonString(header, "typ")
	if !ok || typ != "dpop+jwt" {
		return nil, invalid()
	}
	alg, ok := jsonString(header, "alg")
	if !ok || (alg != "ES256" && alg != "RS256") {
		return nil, invalid()
	}
	for _, field := range []string{"crit", "jku", "x5u", "b64"} {
		if _, ok := header[field]; ok {
			return nil, invalid()
		}
	}
	keyJSON := header["jwk"]
	var fields map[string]json.RawMessage
	if json.Unmarshal(keyJSON, &fields) != nil {
		return nil, invalid()
	}
	for _, n := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u"} {
		if _, ok := fields[n]; ok {
			return nil, invalid()
		}
	}
	for field := range fields {
		if field != strings.ToLower(field) {
			return nil, invalid()
		}
	}
	var jwk jose.JSONWebKey
	if json.Unmarshal(keyJSON, &jwk) != nil || !jwk.Valid() || !jwk.IsPublic() {
		return nil, invalid()
	}
	switch k := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		if alg != "ES256" || k.Curve != elliptic.P256() {
			return nil, invalid()
		}
	case *rsa.PublicKey:
		if alg != "RS256" || k.N.BitLen() < 2048 || k.N.BitLen() > 4096 || k.E < 3 || k.E%2 == 0 {
			return nil, invalid()
		}
	default:
		return nil, invalid()
	}
	jws, e := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.ES256, jose.RS256})
	if e != nil || len(jws.Signatures) != 1 {
		return nil, invalid()
	}
	verified, e := jws.Verify(jwk.Key)
	if e != nil || !bytes.Equal(verified, pb) {
		return nil, invalid()
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(pb, &claims) != nil {
		return nil, invalid()
	}
	jti, ok := jsonString(claims, "jti")
	if !ok || len(jti) == 0 || len(jti) > 200 {
		return nil, invalid()
	}
	method, ok := jsonString(claims, "htm")
	if !ok || method != r.Method {
		return nil, invalid()
	}
	uri, ok := jsonString(claims, "htu")
	if !ok {
		return nil, invalid()
	}
	nonce, _ := jsonString(claims, "nonce")
	ath, _ := jsonString(claims, "ath")
	iat, e := strconv.ParseInt(string(claims["iat"]), 10, 64)
	if e != nil {
		return nil, invalid()
	}
	now := s.now()
	if iat < now.Unix()-60 || iat > now.Unix()+5 {
		return nil, invalid()
	}
	proofURI, e := normalizeURI(uri)
	if e != nil {
		return nil, invalid()
	}
	endpoint, e := normalizeURI(res.Origin() + r.URL.EscapedPath())
	if e != nil || proofURI != endpoint {
		return nil, invalid()
	}
	thumb, e := jwk.Thumbprint(crypto.SHA256)
	if e != nil {
		return nil, invalid()
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	if expectedJKT != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(expectedJKT)) != 1 {
		return nil, invalid()
	}
	if accessToken != "" {
		hash := sha256.Sum256([]byte(accessToken))
		want := base64.RawURLEncoding.EncodeToString(hash[:])
		if subtle.ConstantTimeCompare([]byte(ath), []byte(want)) != 1 {
			return nil, invalid()
		}
	}
	if err := store.CheckRefreshTokensIISupport(ctx, s.Store); err != nil {
		return nil, internal()
	}
	if requireNonce && !s.validNonce(nonce, res, jkt, domain, now) {
		nonce, e := s.newNonce(res, jkt, domain, now)
		if e != nil {
			return nil, internal()
		}
		return nil, &Error{Code: "use_dpop_nonce", Nonce: nonce}
	}
	if err := s.Store.DPoP().UseProof(ctx, res.Tenant.ID, res.Origin(), jkt, jti, now, time.Unix(iat+65, 0)); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrInvalid) {
			return nil, invalid()
		}
		return nil, internal()
	}
	nextNonce := ""
	if requireNonce {
		var err error
		nextNonce, err = s.newNonce(res, jkt, domain, now)
		if err != nil {
			return nil, internal()
		}
	}
	return &Proof{JKT: jkt, Nonce: nextNonce}, nil
}
func uniqueJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if !walkJSON(d, 0) {
		return false
	}
	_, e := d.Token()
	return e == io.EOF
}
func walkJSON(d *json.Decoder, depth int) bool {
	if depth > 16 {
		return false
	}
	v, e := d.Token()
	if e != nil {
		return false
	}
	delim, ok := v.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			name, ok := k.(string)
			if e != nil || !ok || seen[name] {
				return false
			}
			seen[name] = true
			if !walkJSON(d, depth+1) {
				return false
			}
		}
		v, e = d.Token()
		return e == nil && v == json.Delim('}')
	case '[':
		for d.More() {
			if !walkJSON(d, depth+1) {
				return false
			}
		}
		v, e = d.Token()
		return e == nil && v == json.Delim(']')
	}
	return false
}
func normalizeURI(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || strings.Contains(raw, "#") || u.Fragment != "" || u.Host == "" || u.Opaque != "" || (!strings.EqualFold(u.Scheme, "https") && !strings.EqualFold(u.Scheme, "http")) {
		return "", errors.New("invalid URI")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if (scheme == "https" && u.Port() == "443") || (scheme == "http" && u.Port() == "80") {
		host = strings.TrimSuffix(host, ":"+u.Port())
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			v, e := strconv.ParseUint(p[i+1:i+3], 16, 8)
			if e != nil {
				return "", e
			}
			c := byte(v)
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("-._~", rune(c)) {
				b.WriteByte(c)
			} else {
				b.WriteByte('%')
				b.WriteString(strings.ToUpper(p[i+1 : i+3]))
			}
			i += 2
		} else {
			b.WriteByte(p[i])
		}
	}
	return scheme + "://" + host + b.String(), nil
}

func jsonString(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	e := json.Unmarshal(raw, &s)
	return s, e == nil
}
