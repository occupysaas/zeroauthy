// Package dirsync is Google Workspace directory provisioning (Plan 37c
// Phase C): the administrator consent that grants zeroauthy read access to a
// Workspace's Admin SDK Directory API, and the synchronization that creates,
// updates and blocks the users (and selected groups) of a google-apps
// connection.
//
// Every request goes through the federation outbound policy (HTTPS, public
// addresses, bounded responses, no redirects). Refresh and access tokens
// never appear in errors or logs.
package dirsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Page sizes keep each response under the outbound policy's 1 MiB bound.
const (
	userPage   = 200
	groupPage  = 200
	memberPage = 200
	// maxPages bounds one listing (200 000 users, groups or members).
	maxPages = 1000
)

// ErrDirectory is a failed Directory API or token request. Its text holds
// only an HTTP status or a fixed description.
var ErrDirectory = errors.New("dirsync: Google Directory API request failed")

// ErrGrantRevoked reports a refresh token Google no longer accepts
// (invalid_grant): an administrator must consent again.
var ErrGrantRevoked = errors.New("dirsync: the administrator grant was revoked or expired; consent again")

// Client calls Google's token endpoint and Directory API.
type Client struct {
	HTTP         *http.Client
	TokenURL     string
	DirectoryURL string
}

// AccessToken redeems the administrator's refresh token.
func (c *Client) AccessToken(ctx context.Context, clientID, clientSecret, refresh string) (string, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}, "client_secret": {clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("%w: token URL", ErrDirectory)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	status, err := c.do(req, &out)
	if err != nil && status == http.StatusBadRequest && out.Error == "invalid_grant" {
		return "", ErrGrantRevoked
	}
	if err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("%w: token response lacks access_token", ErrDirectory)
	}
	return out.AccessToken, nil
}

// User is a Directory API user resource as JSON (for attribute mapping)
// with the fields synchronization reads.
type User struct {
	Raw          map[string]any
	ID           string
	PrimaryEmail string
	Suspended    bool
	Archived     bool
}

// Group is a Directory API group.
type Group struct {
	ID                 string `json:"id"`
	Email              string `json:"email"`
	Name               string `json:"name"`
	DirectMembersCount string `json:"directMembersCount"`
}

// Member is a Directory API group member.
type Member struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// Users lists the domain's users.
func (c *Client) Users(ctx context.Context, token, domain string, each func(User) error) error {
	q := url.Values{"domain": {domain}, "maxResults": {fmt.Sprint(userPage)}, "projection": {"basic"}, "orderBy": {"email"}}
	return c.list(ctx, token, "/users", q, "users", func(raw json.RawMessage) error {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%w: malformed user", ErrDirectory)
		}
		u := User{Raw: m}
		u.ID, _ = m["id"].(string)
		u.PrimaryEmail, _ = m["primaryEmail"].(string)
		u.Suspended, _ = m["suspended"].(bool)
		u.Archived, _ = m["archived"].(bool)
		return each(u)
	})
}

// Groups lists the domain's groups.
func (c *Client) Groups(ctx context.Context, token, domain string, each func(Group) error) error {
	q := url.Values{"domain": {domain}, "maxResults": {fmt.Sprint(groupPage)}}
	return c.list(ctx, token, "/groups", q, "groups", func(raw json.RawMessage) error {
		var g Group
		if err := json.Unmarshal(raw, &g); err != nil {
			return fmt.Errorf("%w: malformed group", ErrDirectory)
		}
		return each(g)
	})
}

// Group reads one group by ID.
func (c *Client) Group(ctx context.Context, token, id string) (Group, error) {
	var g Group
	req, err := c.get(ctx, token, "/groups/"+url.PathEscape(id), nil)
	if err != nil {
		return g, err
	}
	_, err = c.do(req, &g)
	return g, err
}

// Members lists a group's direct members.
func (c *Client) Members(ctx context.Context, token, groupID string, each func(Member) error) error {
	q := url.Values{"maxResults": {fmt.Sprint(memberPage)}}
	return c.list(ctx, token, "/groups/"+url.PathEscape(groupID)+"/members", q, "members", func(raw json.RawMessage) error {
		var m Member
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("%w: malformed member", ErrDirectory)
		}
		return each(m)
	})
}

// list follows nextPageToken through at most maxPages pages.
func (c *Client) list(ctx context.Context, token, path string, q url.Values, field string, each func(json.RawMessage) error) error {
	for range maxPages {
		req, err := c.get(ctx, token, path, q)
		if err != nil {
			return err
		}
		var page map[string]json.RawMessage
		if _, err := c.do(req, &page); err != nil {
			return err
		}
		var items []json.RawMessage
		if raw, ok := page[field]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return fmt.Errorf("%w: malformed %s page", ErrDirectory, field)
			}
		}
		for _, it := range items {
			if err := each(it); err != nil {
				return err
			}
		}
		var next string
		if raw, ok := page["nextPageToken"]; ok {
			_ = json.Unmarshal(raw, &next)
		}
		if next == "" {
			return nil
		}
		q.Set("pageToken", next)
	}
	return fmt.Errorf("%w: more than %d pages of %s", ErrDirectory, maxPages, field)
}

func (c *Client) get(ctx context.Context, token, path string, q url.Values) (*http.Request, error) {
	u := strings.TrimSuffix(c.DirectoryURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: Directory URL", ErrDirectory)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// do sends req and decodes a JSON body into out. An error never contains the
// response body or request credentials.
func (c *Client) do(req *http.Request, out any) (int, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %s unreachable", ErrDirectory, req.URL.Host)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%w: response unreadable or too large", ErrDirectory)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	decErr := dec.Decode(out)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%w: status %d", ErrDirectory, resp.StatusCode)
	}
	if decErr != nil {
		return resp.StatusCode, fmt.Errorf("%w: malformed JSON", ErrDirectory)
	}
	return resp.StatusCode, nil
}
