package script

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"golang.org/x/net/http/httpguts"
)

// Broker limits.
const (
	maxCalls        = 4
	maxHeaders      = 32
	maxHeaderBytes  = 8192
	maxURLBytes     = 2048
	maxBrokerBodies = 1 << 20
)

// ErrBroker reports a script request the broker refuses or cannot complete.
// The script sees a generic request error; no URL, header or body detail.
var ErrBroker = errors.New("script: profile request refused")

// GetOptions is one script GET.
type GetOptions struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	JSON    bool              `json:"json"`
}

// GetResult is what the script's request callback receives.
type GetResult struct {
	StatusCode int               `json:"statusCode"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"-"`
}

// Broker performs script GETs with the host's bounded HTTP client (in
// production the federation network-policy transport: public pinned
// addresses, no redirects, size and time limits). Scripts cannot choose a
// policy; each execution may make at most four calls.
type Broker struct {
	client *http.Client
}

// NewBroker returns a broker over client.
func NewBroker(client *http.Client) *Broker { return &Broker{client: client} }

// execution is one runner process: its ID binds broker messages to the
// originating tenant and connection, and it counts the calls made.
type execution struct {
	id, tenantID, connectionID string
	mu                         sync.Mutex
	calls                      int
}

func (b *Broker) get(ctx context.Context, ex *execution, o GetOptions) (GetResult, error) {
	ex.mu.Lock()
	ex.calls++
	n := ex.calls
	ex.mu.Unlock()
	if n > maxCalls {
		return GetResult{}, fmt.Errorf("%w: more than %d requests", ErrBroker, maxCalls)
	}
	u, err := url.Parse(o.URL)
	if err != nil || len(o.URL) > maxURLBytes || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.Contains(o.URL, "#") {
		return GetResult{}, fmt.Errorf("%w: target must be an absolute https URL", ErrBroker)
	}
	if len(o.Headers) > maxHeaders {
		return GetResult{}, fmt.Errorf("%w: too many headers", ErrBroker)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return GetResult{}, fmt.Errorf("%w: bad request", ErrBroker)
	}
	for k, v := range o.Headers {
		if !httpguts.ValidHeaderFieldName(k) || !httpguts.ValidHeaderFieldValue(v) || len(k)+len(v) > maxHeaderBytes {
			return GetResult{}, fmt.Errorf("%w: invalid header", ErrBroker)
		}
		switch strings.ToLower(k) {
		case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization":
			return GetResult{}, fmt.Errorf("%w: header not allowed", ErrBroker)
		}
		req.Header.Set(k, v)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return GetResult{}, fmt.Errorf("%w: request failed", ErrBroker)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return GetResult{}, fmt.Errorf("%w: redirect refused", ErrBroker)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBrokerBodies+1))
	if err != nil || len(body) > maxBrokerBodies {
		return GetResult{}, fmt.Errorf("%w: response unreadable or too large", ErrBroker)
	}
	h := map[string]string{}
	for k, vs := range resp.Header {
		if len(vs) > 0 && len(h) < maxHeaders {
			h[strings.ToLower(k)] = vs[0]
		}
	}
	return GetResult{StatusCode: resp.StatusCode, Headers: h, Body: string(body)}, nil
}
