package protection

import (
	"bufio"
	"context"
	"crypto/sha1" // Lookup key only; never used to store passwords.
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/protectionrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var (
	ErrBreachUnavailable = errors.New("password security check temporarily unavailable; try again later")
	ErrPasswordLeaked    = errors.New("this password has appeared in a data breach; choose a different password")
)

type BreachChecker interface {
	Check(context.Context, string) (bool, error)
}

const rangeLimit = 2 * 1024 * 1024

type prefixEntry struct {
	suffixes map[string]bool
	expires  time.Time
}
type RangeChecker struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]prefixEntry
	now    func() time.Time
}

// NewRangeChecker accepts a transport, never an endpoint. A nil transport uses
// the standard HTTPS transport; tests replace transport without changing URLs.
func NewRangeChecker(transport http.RoundTripper) *RangeChecker {
	return &RangeChecker{client: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cache: make(map[string]prefixEntry), now: time.Now}
}
func passwordDigest(password string) string { return fmt.Sprintf("%X", sha1.Sum([]byte(password))) }
func hexCount(line string, size int, padding bool) (string, uint64, error) {
	parts := strings.Split(line, ":")
	if len(parts) != 2 || len(parts[0]) != size || len(parts[1]) == 0 || len(parts[1]) > 20 {
		return "", 0, ErrBreachUnavailable
	}
	for _, c := range parts[0] {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return "", 0, ErrBreachUnavailable
		}
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return "", 0, ErrBreachUnavailable
		}
	}
	count, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || (!padding && count == 0) {
		return "", 0, ErrBreachUnavailable
	}
	return strings.ToUpper(parts[0]), count, nil
}
func (c *RangeChecker) Check(ctx context.Context, password string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, ErrBreachUnavailable
	}
	hash := passwordDigest(password)
	prefix, suffix := hash[:5], hash[5:]
	c.mu.Lock()
	entry, ok := c.cache[prefix]
	c.mu.Unlock()
	if ok && c.now().Before(entry.expires) {
		return entry.suffixes[suffix], nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return false, ErrBreachUnavailable
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := c.client.Do(req)
	if err != nil {
		return false, ErrBreachUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, ErrBreachUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, rangeLimit+1))
	if err != nil || len(body) > rangeLimit || len(body) == 0 {
		return false, ErrBreachUnavailable
	}
	suffixes := make(map[string]bool)
	scan := bufio.NewScanner(strings.NewReader(string(body)))
	scan.Buffer(make([]byte, 128), 128)
	for scan.Scan() {
		key, count, err := hexCount(scan.Text(), 35, true)
		if err != nil {
			return false, err
		}
		if _, exists := suffixes[key]; exists {
			return false, ErrBreachUnavailable
		}
		suffixes[key] = count > 0
	}
	if scan.Err() != nil || len(suffixes) == 0 {
		return false, ErrBreachUnavailable
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.cache {
		if !now.Before(v.expires) {
			delete(c.cache, k)
		}
	}
	if len(c.cache) >= 1024 {
		var oldest string
		var expiry time.Time
		for k, v := range c.cache {
			if oldest == "" || v.expires.Before(expiry) {
				oldest, expiry = k, v.expires
			}
		}
		delete(c.cache, oldest)
	}
	c.cache[prefix] = prefixEntry{suffixes, now.Add(5 * time.Minute)}
	return suffixes[suffix], nil
}

// CheckPassword re-reads policy so edits take effect on the next submission.
// No underlying error, submitted password or digest crosses this boundary.
func (s *Service) CheckPassword(ctx context.Context, tenant *store.Tenant, stage, password string) error {
	if tenant == nil {
		return ErrBreachUnavailable
	}
	current, err := s.Store.Tenants().Get(ctx, tenant.ID)
	if err != nil {
		return ErrBreachUnavailable
	}
	p := current.ProtectionSettings
	if !current.ProtectionSettingsInitialized {
		p = protectionrules.Defaults()
	}
	policy := p.BreachedPassword
	var shields []string
	switch stage {
	case "login":
		shields = policy.Shields
	case "pre-user-registration":
		shields = policy.Stage.PreUserRegistration.Shields
	case "pre-change-password":
		shields = policy.Stage.PreChangePassword.Shields
	default:
		return ErrBreachUnavailable
	}
	if !policy.Enabled {
		return nil
	}
	hit := false
	err = ErrBreachUnavailable
	if s.BreachChecker != nil {
		hit, err = s.BreachChecker.Check(ctx, password)
	}
	if err != nil {
		s.Event(ctx, tenant.ID, "breached-password", "unavailable", "")
		if slices.Contains(shields, "block") {
			return ErrBreachUnavailable
		}
		return nil
	}
	if !hit {
		return nil
	}
	s.Event(ctx, tenant.ID, "breached-password", "detected", "")
	s.notifications(ctx, tenant.ID, "breached-password", shields)
	if slices.Contains(shields, "block") {
		return ErrPasswordLeaked
	}
	return nil
}
