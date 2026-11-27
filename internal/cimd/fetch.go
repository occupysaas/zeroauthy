// Package cimd fetches, validates and maps OAuth Client ID Metadata
// Documents (Plan 41b, draft-ietf-oauth-client-id-metadata-document,
// D-0090): a client whose client_id is an HTTPS URL describes itself in
// the JSON document at that URL.
package cimd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation"
)

// Limits (D-0090, LR41b-3).
const (
	MaxDocumentBytes = 64 << 10
	MaxURLLength     = 200
	MinCache         = 5 * time.Minute
	MaxCache         = 24 * time.Hour
	// HardExpiry is how long after the last good fetch a cached document
	// still serves when refreshing fails (R41-7).
	HardExpiry     = 24 * time.Hour
	requestTimeout = 10 * time.Second
	maxJWKSKeys    = 10
)

// ErrRetrieval wraps every reason a document could not be fetched.
var ErrRetrieval = errors.New("cimd: the metadata document could not be retrieved")

// CheckURL reports why raw cannot be a Client ID Metadata Document URL:
// it must be an https URL of at most 200 characters with a path other than
// "/", no fragment, no credentials and no dot segments.
func CheckURL(raw string) error {
	if raw == "" || len(raw) > MaxURLLength {
		return fmt.Errorf("the URL must be 1 to %d characters", MaxURLLength)
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Scheme != "https" || u.Host == "" || u.Opaque != "":
		return errors.New("the URL must be an absolute https URL")
	case u.User != nil:
		return errors.New("the URL must not contain credentials")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("the URL must not contain a fragment")
	case u.Path == "" || u.Path == "/":
		return errors.New("the URL must have a path")
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		if seg == "." || seg == ".." {
			return errors.New("the URL must not contain dot segments")
		}
	}
	return nil
}

// IsCandidate reports whether a client_id looks like a Client ID Metadata
// Document URL rather than a client ID.
func IsCandidate(clientID string) bool { return strings.HasPrefix(clientID, "https://") }

// Fetcher fetches documents and JWKS under the federation outbound policy
// (HTTPS, public addresses at every dial, no proxy, no redirects), at most
// 64 KiB within 10 s.
type Fetcher struct {
	client *http.Client
	policy federation.NetworkPolicy
}

// NewFetcher returns a fetcher for policy; the zero policy is production.
func NewFetcher(policy federation.NetworkPolicy) *Fetcher {
	if policy.MaxResponseBytes <= 0 || policy.MaxResponseBytes > MaxDocumentBytes {
		policy.MaxResponseBytes = MaxDocumentBytes
	}
	timeout := policy.RequestTimeout
	if timeout <= 0 {
		timeout = requestTimeout
	}
	return &Fetcher{client: &http.Client{Transport: federation.NewTransport(policy), Timeout: timeout}, policy: policy}
}

// Document is a fetched metadata document.
type Document struct {
	URL     string
	Members map[string]json.RawMessage
	// MaxAge is how long the document may be cached: its Cache-Control
	// max-age bounded to MinCache..MaxCache.
	MaxAge time.Duration
}

// Fetch retrieves the document at rawURL. It never sends cookies, user
// data or credentials.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (*Document, error) {
	if err := CheckURL(rawURL); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRetrieval, err)
	}
	body, header, err := f.get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	members, err := object(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRetrieval, err)
	}
	return &Document{URL: rawURL, Members: members, MaxAge: maxAge(header.Get("Cache-Control"))}, nil
}

func (f *Fetcher) get(ctx context.Context, rawURL string) ([]byte, http.Header, error) {
	if err := f.policy.CheckEndpoint(rawURL); err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRetrieval, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrRetrieval, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRetrieval, cause(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%w: the server answered HTTP %d", ErrRetrieval, resp.StatusCode)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || (mt != "application/json" && !(strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))) {
		return nil, nil, fmt.Errorf("%w: the content type is not application/json", ErrRetrieval)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRetrieval, cause(err))
	}
	return body, resp.Header, nil
}

// cause unwraps the url.Error the client adds, keeping the policy and size
// errors identifiable.
func cause(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, federation.ErrResponseTooLarge) {
		return errors.New("the document is larger than 64 KiB")
	}
	return err
}

func object(body []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return nil, errors.New("the document is not a JSON object")
	}
	return m, nil
}

// maxAge reads Cache-Control's max-age, bounded to MinCache..MaxCache;
// absent, unparsable or no-store means MinCache.
func maxAge(cc string) time.Duration {
	for _, d := range strings.Split(cc, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(d), "=")
		if !strings.EqualFold(name, "max-age") {
			continue
		}
		n, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err != nil || n < 0 {
			return MinCache
		}
		age := time.Duration(min(n, int64(MaxCache/time.Second))) * time.Second
		return min(max(age, MinCache), MaxCache)
	}
	return MinCache
}

// FetchJWKS retrieves the keys at a jwks_uri under the same policy.
func (f *Fetcher) FetchJWKS(ctx context.Context, rawURL string) ([]json.RawMessage, error) {
	body, _, err := f.get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	return parseJWKS(body)
}

func parseJWKS(raw []byte) ([]json.RawMessage, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) == 0 {
		return nil, errors.New("the JWKS must be an object with a non-empty keys list")
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("the JWKS has more than %d keys", maxJWKSKeys)
	}
	return set.Keys, nil
}
