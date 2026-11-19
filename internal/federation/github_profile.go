package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// githubAPIVersion is the pinned X-GitHub-Api-Version (inventory
// provider_protocol.github.api_version).
const githubAPIVersion = "2026-03-10"

// githubPresent is the rate-limit signal value meaning "header present".
const githubPresent = "present"

// githubRateLimitSignals are the inventory's provider_protocol.github
// rate_limit_signals, in order: a 403 or 429 is a rate limit when
// x-ratelimit-remaining is exactly "0" or retry-after is present. Runtime
// never reads the inventory; a test keeps these equal to it.
var githubRateLimitSignals = []struct {
	Status        int
	Header, Value string
}{
	{http.StatusForbidden, "x-ratelimit-remaining", "0"},
	{http.StatusTooManyRequests, "x-ratelimit-remaining", "0"},
	{http.StatusForbidden, "retry-after", githubPresent},
	{http.StatusTooManyRequests, "retry-after", githubPresent},
}

// githubProviderDataFields are the /user fields kept as identity provider data
// (inventory github_profile.provider_data).
var githubProviderDataFields = []string{"login", "html_url", "blog", "company", "location", "bio",
	"public_repos", "followers", "following", "created_at", "updated_at"}

func githubRateLimited(status int, h http.Header) bool {
	for _, s := range githubRateLimitSignals {
		if s.Status != status {
			continue
		}
		if s.Value == githubPresent && len(h.Values(s.Header)) > 0 || s.Value != githubPresent && h.Get(s.Header) == s.Value {
			return true
		}
	}
	return false
}

// githubGET performs one bounded GitHub REST request with the access token.
// Errors carry neither the token nor the body.
func (ps *Providers) githubGET(ctx context.Context, url, token string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: bad URL", ErrProviderResponse)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", "zeroauthy")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ps.client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: github request: %w", ErrProviderResponse, redact(err))
	}
	body, err := readAll(resp)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: github response: %w", ErrProviderResponse, redact(err))
	}
	return resp.StatusCode, resp.Header, body, nil
}

// githubUser fetches /user and maps it. The id must be a JSON integer in
// 1…2⁶³−1, never read through float64.
func (ps *Providers) githubUser(ctx context.Context, apiBase, token string) (Profile, error) {
	status, _, body, err := ps.githubGET(ctx, apiBase+"/user", token)
	if err != nil {
		return Profile{}, err
	}
	if status != http.StatusOK {
		return Profile{}, fmt.Errorf("%w: github user status %d", ErrProviderResponse, status)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var u map[string]any
	if err := dec.Decode(&u); err != nil || u == nil || dec.More() {
		return Profile{}, fmt.Errorf("%w: malformed github user", ErrProviderResponse)
	}
	id, isNum := u["id"].(json.Number)
	if !isNum || !rules.ValidGitHubSubject(id.String()) {
		return Profile{}, fmt.Errorf("%w: github id must be a positive 64-bit integer", ErrProfile)
	}
	return githubProfile(id.String(), u)
}

// githubProfile maps a /user object. Optional fields of the wrong type or
// shape are dropped; provider data is bounded by the profile limit.
func githubProfile(sub string, u map[string]any) (Profile, error) {
	claims := map[string]any{}
	login, _ := u["login"].(string)
	if login != "" {
		claims["nickname"] = login
		claims["name"] = login
	}
	if name, _ := u["name"].(string); name != "" {
		claims["name"] = name
	}
	if avatar, ok := u["avatar_url"].(string); ok {
		claims["picture"] = avatar
	}
	p, err := profileFromClaims(sub, claims)
	if err != nil {
		return Profile{}, err
	}
	if p.Name == nil && p.Nickname != nil {
		p.Name = p.Nickname // an over-long name falls back to login
	}
	pd := map[string]any{}
	for _, k := range githubProviderDataFields {
		switch v := u[k].(type) {
		case string:
			pd[k] = v
		case json.Number:
			if n, err := strconv.ParseInt(v.String(), 10, 64); err == nil && n >= 0 {
				pd[k] = float64(n) // the store's number form
			}
		}
	}
	if enc, err := json.Marshal(pd); err != nil || len(enc) > maxProfileBytes {
		return Profile{}, fmt.Errorf("%w: github provider data is larger than %d bytes", ErrProfile, maxProfileBytes)
	}
	if len(pd) > 0 {
		p.ProviderData = pd
	}
	return p, nil
}

// githubEmails fetches one page of /user/emails and returns the verified
// primary address (spec §6). No verified primary, or a 403/404 without
// rate-limit signals, is ErrEmailRequired; 401, rate limits, any 429, 5xx,
// transport errors and malformed bodies are provider failures.
func (ps *Providers) githubEmails(ctx context.Context, apiBase, token string) (string, error) {
	status, h, body, err := ps.githubGET(ctx, apiBase+"/user/emails?per_page=100", token)
	if err != nil {
		return "", err
	}
	switch {
	case status == http.StatusOK:
	case githubRateLimited(status, h) || status == http.StatusTooManyRequests:
		return "", fmt.Errorf("%w: github emails rate limited (status %d)", ErrProviderResponse, status)
	case status == http.StatusForbidden || status == http.StatusNotFound:
		return "", fmt.Errorf("%w: github emails status %d", ErrEmailRequired, status)
	default:
		return "", fmt.Errorf("%w: github emails status %d", ErrProviderResponse, status)
	}
	var list []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return "", fmt.Errorf("%w: malformed github emails", ErrProviderResponse)
	}
	for _, e := range list {
		if !e.Primary {
			continue
		}
		if !e.Verified || e.Email == "" {
			break
		}
		if _, err := profileString("email", e.Email, 254); err != nil {
			return "", err
		}
		return e.Email, nil
	}
	return "", ErrEmailRequired
}
