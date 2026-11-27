// Package oauth1sig signs OAuth 1.0a requests (RFC 5849 §3.4): the signature
// base string, HMAC-SHA1 and RSA-SHA1 signatures and the Authorization
// header. PLAINTEXT is not implemented (LR39b-9). It is a leaf package shared
// by the federation provider and the profile script broker.
package oauth1sig

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"sort"
	"strings"
)

// Signature methods.
const (
	HMACSHA1 = "HMAC-SHA1"
	RSASHA1  = "RSA-SHA1"
)

// ErrSign reports an unsignable request; it never carries a credential.
var ErrSign = errors.New("oauth1sig: request cannot be signed")

// Credentials sign one request. RSAKey, when set, selects RSA-SHA1 and
// ConsumerSecret is unused; otherwise HMAC-SHA1 with ConsumerSecret. Token
// and TokenSecret are empty for the temporary-credential request.
type Credentials struct {
	ConsumerKey    string
	ConsumerSecret string
	RSAKey         *rsa.PrivateKey
	Token          string
	TokenSecret    string
}

func (c Credentials) method() string {
	if c.RSAKey != nil {
		return RSASHA1
	}
	return HMACSHA1
}

// extraKeys are the protocol parameters a caller may add.
var extraKeys = []string{"oauth_callback", "oauth_verifier", "oauth_nonce", "oauth_timestamp", "oauth_version"}

// Params returns the protocol parameters to sign: the consumer key, the
// signature method, the token when set, and extra (callback, verifier,
// nonce, timestamp, version).
func Params(c Credentials, extra map[string]string) (map[string]string, error) {
	if c.ConsumerKey == "" || (c.RSAKey == nil && c.ConsumerSecret == "") {
		return nil, fmt.Errorf("%w: consumer credentials are missing", ErrSign)
	}
	p := map[string]string{"oauth_consumer_key": c.ConsumerKey, "oauth_signature_method": c.method()}
	if c.Token != "" {
		p["oauth_token"] = c.Token
	}
	for k, v := range extra {
		if !slices.Contains(extraKeys, k) {
			return nil, fmt.Errorf("%w: parameter %q is reserved or not a protocol parameter", ErrSign, k)
		}
		p[k] = v
	}
	return p, nil
}

// Encode is RFC 5849 §3.6 percent-encoding: every byte but the unreserved
// characters ALPHA, DIGIT, "-", ".", "_" and "~".
func Encode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// BaseString is the signature base string (RFC 5849 §3.4.1): the method, the
// normalized base URI, and the sorted encoded parameters from the query,
// the form body and oauth (without oauth_signature).
func BaseString(method, rawURL string, form url.Values, oauth map[string]string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("%w: invalid URL", ErrSign)
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", fmt.Errorf("%w: invalid query", ErrSign)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80" || scheme == "https" && port == "443") {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	var pairs [][2]string
	add := func(k, v string) { pairs = append(pairs, [2]string{Encode(k), Encode(v)}) }
	for k, vs := range query {
		for _, v := range vs {
			add(k, v)
		}
	}
	for k, vs := range form {
		for _, v := range vs {
			add(k, v)
		}
	}
	for k, v := range oauth {
		if k != "oauth_signature" {
			add(k, v)
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})
	norm := make([]string, len(pairs))
	for i, p := range pairs {
		norm[i] = p[0] + "=" + p[1]
	}
	return strings.ToUpper(method) + "&" + Encode(scheme+"://"+host+path) + "&" + Encode(strings.Join(norm, "&")), nil
}

// Sign returns the base64 signature of the request.
func Sign(c Credentials, method, rawURL string, form url.Values, oauth map[string]string) (string, error) {
	base, err := BaseString(method, rawURL, form, oauth)
	if err != nil {
		return "", err
	}
	if c.RSAKey != nil {
		sum := sha1.Sum([]byte(base))
		sig, err := rsa.SignPKCS1v15(rand.Reader, c.RSAKey, crypto.SHA1, sum[:])
		if err != nil {
			return "", fmt.Errorf("%w: RSA-SHA1", ErrSign)
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	}
	mac := hmac.New(sha1.New, []byte(Encode(c.ConsumerSecret)+"&"+Encode(c.TokenSecret)))
	mac.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// Header signs the request and returns its Authorization header value.
// extra may hold only oauth_callback and oauth_verifier.
func Header(c Credentials, method, rawURL string, form url.Values, extra map[string]string, nonce, timestamp string) (string, error) {
	all := map[string]string{"oauth_nonce": nonce, "oauth_timestamp": timestamp, "oauth_version": "1.0"}
	for k, v := range extra {
		if k != "oauth_callback" && k != "oauth_verifier" {
			return "", fmt.Errorf("%w: parameter %q may not be set", ErrSign, k)
		}
		all[k] = v
	}
	params, err := Params(c, all)
	if err != nil {
		return "", err
	}
	sig, err := Sign(c, method, rawURL, form, params)
	if err != nil {
		return "", err
	}
	params["oauth_signature"] = sig
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = Encode(k) + `="` + Encode(params[k]) + `"`
	}
	return "OAuth " + strings.Join(parts, ", "), nil
}

// Nonce returns 128 random bits, hex-free URL-safe base64.
func Nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// MinRSABits is the smallest RSA-SHA1 consumer key accepted.
const MinRSABits = 2048

// ParsePrivateKey reads an RSA-SHA1 consumer key: one PEM block, PKCS #1 or
// PKCS #8, at least MinRSABits.
func ParsePrivateKey(text string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, fmt.Errorf("%w: client_secret must be one PEM RSA private key", ErrSign)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid PKCS #1 key", ErrSign)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		rk, ok := k.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, fmt.Errorf("%w: invalid PKCS #8 RSA key", ErrSign)
		}
		key = rk
	default:
		return nil, fmt.Errorf("%w: client_secret must be an RSA private key", ErrSign)
	}
	if key.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("%w: RSA key must have at least %d bits", ErrSign, MinRSABits)
	}
	return key, nil
}
