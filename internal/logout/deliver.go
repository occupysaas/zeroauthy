package logout

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// deliveryClient retains injected test CAs, but always installs guarded DNS
// dialing, certificate verification, no proxy, no cookies and no redirects.
func (s *Service) deliveryClient() *http.Client {
	client := http.Client{}
	if s.HTTP != nil {
		client = *s.HTTP
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if existing, ok := client.Transport.(*http.Transport); ok {
		transport = existing.Clone()
	}
	transport.Proxy = nil
	transport.DialContext = httpx.GuardedDialer(s.AllowPrivateNetworks)
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = false
	transport.TLSClientConfig.ServerName = ""
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Second
	client.Transport = transport
	client.Timeout = 5 * time.Second
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}
func (s *Service) receiverAllowed(ctx context.Context, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || strings.ContainsAny(raw, "{}#") {
		return httpx.ErrBlockedAddress
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "auth0.com" || strings.HasSuffix(host, ".auth0.com") {
		return httpx.ErrBlockedAddress
	}
	owner, err := s.Store.Tenants().GetByDomain(ctx, tenant.NormalizeHost(parsed.Host))
	if err == nil && owner != nil {
		return httpx.ErrBlockedAddress
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if parsed.Port() != "" {
		owner, err := s.Store.Tenants().GetByDomain(ctx, tenant.NormalizeHost(host))
		if err == nil && owner != nil {
			return httpx.ErrBlockedAddress
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && !s.AllowPrivateNetworks && !rules.PublicAddr(ip) {
		return httpx.ErrBlockedAddress
	}
	return nil
}

// Deliver performs one bounded attempt from a sealed immutable snapshot. The
// existing job worker owns claim/finish; retry scheduling stays durable.
func (s *Service) Deliver(ctx context.Context, job *store.ActionJob) *store.ActionJob {
	if job == nil || ctx.Err() != nil {
		return nil
	}
	next := *job
	next.LeaseUntil = time.Time{}
	next.UpdatedAt = s.now()
	next.Status = "failed"
	content, err := s.open(job)
	if err != nil || !s.now().Before(content.Deadline) {
		return &next
	}
	if err = s.receiverAllowed(ctx, content.URL); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return &next
	}
	include := content.IncludeMetadata
	client := &store.Client{TenantID: job.TenantID, ClientID: content.ClientID, OIDCLogout: &store.OIDCLogout{IncludeSessionMetadata: &include}}
	raw, err := s.token(ctx, job.TenantID, content.Issuer, client, &content.Session)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return s.retry(&next, content.Deadline)
	}
	requestCtx := logscrub.WithCredentials(ctx, raw, content.URL)
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, content.URL, strings.NewReader(url.Values{"logout_token": []string{raw}}.Encode()))
	if err != nil {
		return &next
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	transport := s.deliveryClient()
	defer transport.CloseIdleConnections()
	response, err := transport.Do(request)
	if ctx.Err() != nil {
		if response != nil {
			response.Body.Close()
		}
		return nil
	}
	if err != nil {
		if errors.Is(err, httpx.ErrBlockedAddress) {
			return &next
		}
		return s.retry(&next, content.Deadline)
	}
	response.Body.Close() // Never read or retain a receiver's credential echo.
	if response.StatusCode == 200 || response.StatusCode == 204 {
		next.Status = "done"
		return &next
	}
	if response.StatusCode >= 500 {
		return s.retry(&next, content.Deadline)
	}
	return &next
}
func (s *Service) retry(next *store.ActionJob, deadline time.Time) *store.ActionJob {
	delay := time.Second << min(max(next.Attempts-1, 0), 6)
	next.NextAt = s.now().Add(delay)
	if !next.NextAt.Before(deadline) {
		next.NextAt = deadline
	}
	if s.now().Before(deadline) {
		next.Status = "pending"
	}
	return next
}

// Finished is called only after the fenced terminal-state write succeeds.
// Logs identify the client and receiver host, never the URL or signed token.
func (s *Service) Finished(ctx context.Context, job *store.ActionJob) {
	if job == nil || (job.Status != "done" && job.Status != "failed") {
		return
	}
	kind := "oidc_backchannel_logout_failed"
	if job.Status == "done" {
		kind = "oidc_backchannel_logout_succeeded"
	}
	event := logs.Event{TenantID: job.TenantID, Type: kind, Date: s.now()}
	if content, err := s.open(job); err == nil {
		event.ClientID = content.ClientID
		event.Details = map[string]any{"initiator": string(content.Initiator)}
		if parsed, err := url.Parse(content.URL); err == nil && parsed.Hostname() != "" {
			event.Details["receiver_host"] = parsed.Hostname()
		}
	}
	logs.RecordEvent(ctx, s.Recorder, event)
}
