package certificates

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
)

// digitalOceanAPI is the fixed provider origin; no tenant or request content
// can change it or the authorization sent to it.
const digitalOceanAPI = "https://api.digitalocean.com"

const providerDeadline = 10 * time.Second

// ProviderRateLimit is a provider refusal with its Retry-After.
type ProviderRateLimit struct{ RetryAfter time.Duration }

func (e *ProviderRateLimit) Error() string {
	return fmt.Sprintf("dns provider rate limited the request; retry after %s", e.RetryAfter)
}

// DigitalOcean manages TXT records through the DigitalOcean domain-records
// API with a token from a deployment file. Errors never include the token
// or response bodies.
type DigitalOcean struct {
	token    string
	endpoint string
	client   *http.Client
	deadline time.Duration
}

// DigitalOceanOption adjusts the adapter; only tests use WithEndpoint.
type DigitalOceanOption func(*DigitalOcean)

// WithEndpoint points the adapter at a local fake API (tests only).
func WithEndpoint(endpoint string, client *http.Client, deadline time.Duration) DigitalOceanOption {
	return func(d *DigitalOcean) {
		d.endpoint, d.deadline = strings.TrimSuffix(endpoint, "/"), deadline
		if client != nil {
			d.client = client
		}
	}
}

func NewDigitalOcean(token string, opts ...DigitalOceanOption) *DigitalOcean {
	d := &DigitalOcean{token: token, endpoint: digitalOceanAPI, client: &http.Client{}, deadline: providerDeadline}
	for _, o := range opts {
		o(d)
	}
	return d
}

type doRecord struct {
	ID   int64  `json:"id,omitempty"`
	Type string `json:"type"`
	Name string `json:"name"`
	Data string `json:"data"`
	TTL  int    `json:"ttl,omitempty"`
}

// relative maps a fully qualified name to the zone-relative record name.
func relative(zone, name string) (string, string, error) {
	z, err := hostname.NormalizeDNSName(zone)
	if err != nil {
		return "", "", fmt.Errorf("dns provider: invalid zone")
	}
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	if n == z {
		return z, "@", nil
	}
	rel, ok := strings.CutSuffix(n, "."+z)
	if !ok || rel == "" {
		return "", "", fmt.Errorf("dns provider: %q is not inside zone %q", n, z)
	}
	return z, rel, nil
}

func (d *DigitalOcean) do(ctx context.Context, method, path string, query url.Values, body any, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, d.deadline)
	defer cancel()
	u := d.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, errors.New("dns provider: request could not be built")
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, fmt.Errorf("dns provider: %s %s: %w", method, path, ctx.Err())
		}
		return 0, fmt.Errorf("dns provider: %s %s failed", method, path)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		secs, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
		return resp.StatusCode, &ProviderRateLimit{RetryAfter: time.Duration(secs) * time.Second}
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("dns provider: %s %s returned HTTP %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("dns provider: malformed %s %s response", method, path)
		}
	}
	return resp.StatusCode, nil
}

// Find returns the first TXT record at name with exactly value, and how many
// such records exist.
func (d *DigitalOcean) Find(ctx context.Context, zone, name, value string) (DNSRecord, int, error) {
	z, _, err := relative(zone, name)
	if err != nil {
		return DNSRecord{}, 0, err
	}
	fqdn := strings.TrimSuffix(strings.ToLower(name), ".")
	var out struct {
		Records []doRecord `json:"domain_records"`
	}
	if _, err := d.do(ctx, http.MethodGet, "/v2/domains/"+url.PathEscape(z)+"/records", url.Values{"type": {"TXT"}, "name": {fqdn}, "per_page": {"200"}}, nil, &out); err != nil {
		return DNSRecord{}, 0, err
	}
	var first DNSRecord
	n := 0
	for _, r := range out.Records {
		if r.Type == "TXT" && r.Data == value {
			if n == 0 {
				first = DNSRecord{ID: strconv.FormatInt(r.ID, 10), Zone: z, Name: fqdn, Value: value}
			}
			n++
		}
	}
	return first, n, nil
}

// Present creates the TXT value unless an identical one exists; then it
// reports Created false, so CleanUp will never remove it.
func (d *DigitalOcean) Present(ctx context.Context, zone, name, value string) (DNSRecord, error) {
	z, rel, err := relative(zone, name)
	if err != nil {
		return DNSRecord{}, err
	}
	if existing, n, err := d.Find(ctx, zone, name, value); err != nil {
		return DNSRecord{}, err
	} else if n > 0 {
		return existing, nil
	}
	var out struct {
		Record doRecord `json:"domain_record"`
	}
	if _, err := d.do(ctx, http.MethodPost, "/v2/domains/"+url.PathEscape(z)+"/records", nil, doRecord{Type: "TXT", Name: rel, Data: value, TTL: 30}, &out); err != nil {
		return DNSRecord{}, err
	}
	if out.Record.ID == 0 {
		return DNSRecord{}, errors.New("dns provider: create returned no record ID")
	}
	return DNSRecord{ID: strconv.FormatInt(out.Record.ID, 10), Zone: z, Name: strings.TrimSuffix(strings.ToLower(name), "."), Value: value, Created: true}, nil
}

// CleanUp deletes exactly the record this deployment created, by ID.
func (d *DigitalOcean) CleanUp(ctx context.Context, rec DNSRecord) error {
	if !rec.Created || rec.ID == "" {
		return errors.New("dns provider: refusing to delete a record this deployment did not create")
	}
	if _, err := strconv.ParseInt(rec.ID, 10, 64); err != nil {
		return errors.New("dns provider: invalid record ID")
	}
	code, err := d.do(ctx, http.MethodDelete, "/v2/domains/"+url.PathEscape(rec.Zone)+"/records/"+rec.ID, nil, nil, nil)
	if code == http.StatusNotFound {
		return nil // already gone
	}
	return err
}
