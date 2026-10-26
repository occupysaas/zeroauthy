package customdomain

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ProxyKeyHeader carries a self-managed domain's proxy key.
const ProxyKeyHeader = "cname-api-key"

var (
	// ErrNotCustomDomain: the host is not an API custom domain or origin
	// alias; ordinary tenant resolution applies.
	ErrNotCustomDomain = errors.New("customdomain: not a custom domain host")
	// ErrUnknownHost: a custom-domain name that is not currently serving.
	ErrUnknownHost = errors.New("customdomain: the custom domain is not serving")
	// ErrProxyRejected: missing TLS, untrusted peer or wrong proxy key.
	ErrProxyRejected = errors.New("customdomain: the proxy is not authorized for this domain")
	// ErrMisdirected: Host and SNI disagree, or a forwarded host names a
	// custom domain.
	ErrMisdirected = errors.New("customdomain: misdirected request")
	// ErrClientIP: the configured client IP header is missing or invalid.
	ErrClientIP = errors.New("customdomain: invalid client IP header")
)

// ProxyPolicy is deployment proxy trust. Trusted lists immediate-peer CIDRs
// (server.trusted_proxy_cidrs); LegacyTrust is server.trust_proxy_headers,
// which keeps its forwarded host/IP behavior for ordinary hosts, restricted
// to Trusted peers when any are configured.
type ProxyPolicy struct {
	Trusted     []netip.Prefix
	LegacyTrust bool
}

func (p ProxyPolicy) trusts(peer netip.Addr) bool {
	for _, pr := range p.Trusted {
		if pr.Contains(peer) {
			return true
		}
	}
	return false
}

func (p ProxyPolicy) legacy(peer netip.Addr) bool {
	return p.LegacyTrust && (len(p.Trusted) == 0 || p.trusts(peer))
}

// Admission is an authenticated custom-domain request.
type Admission struct {
	TenantID, PublicHost, ClientIP, DomainID string

	public *PublicDomain // template context: public name and metadata only
}

// forwarding headers never reach handlers behind an admitted custom domain.
// That includes every supported client IP header, used or not.
var forwarding = []string{ProxyKeyHeader, "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Forwarded", "X-Real-Ip",
	"True-Client-Ip", "Cf-Connecting-Ip", "X-Azure-Clientip"}

func peerAddr(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap().WithZone("")
}

// Admit authenticates a request whose Host is an API custom domain or a
// private origin alias. Managed domains are direct TLS (Host must equal
// SNI); self-managed domains need TLS from a trusted peer carrying that
// domain's proxy key. Store failures are returned as they are (503).
func (s *Service) Admit(r *http.Request) (Admission, error) {
	host, err := hostname.NormalizeOperatorHost(r.Host)
	if err != nil {
		return Admission{}, ErrNotCustomDomain
	}
	b, err := s.st.CustomDomains().GetHost(r.Context(), host)
	if errors.Is(err, store.ErrNotFound) || err == nil && b.Kind != store.HostPublic && b.Kind != store.HostOrigin {
		return Admission{}, ErrNotCustomDomain
	}
	if err != nil {
		return Admission{}, err
	}
	d, err := s.st.CustomDomains().Get(r.Context(), b.TenantID, b.DomainID)
	if errors.Is(err, store.ErrNotFound) {
		return Admission{}, ErrUnknownHost
	}
	if err != nil {
		return Admission{}, err
	}
	usable, err := ServingUsable(r.Context(), s.st, d, s.clock())
	if err != nil {
		return Admission{}, err
	}
	if !b.Active || b.Generation != d.Generation || !usable || b.Kind == store.HostOrigin && d.Type != TypeSelfManaged {
		return Admission{}, ErrUnknownHost
	}
	if r.TLS == nil {
		return Admission{}, ErrProxyRejected
	}
	if sni, err := hostname.NormalizeOperatorHost(r.TLS.ServerName); err != nil || sni != host {
		return Admission{}, ErrMisdirected
	}
	peer := peerAddr(r)
	adm := Admission{TenantID: d.TenantID, PublicHost: d.Domain, DomainID: d.ID, ClientIP: peer.String(), public: publicOf(d)}
	if d.Type == TypeManaged {
		return adm, nil
	}
	key := r.Header.Values(ProxyKeyHeader)
	if !peer.IsValid() || !s.cfg.Proxy.trusts(peer) || len(key) != 1 || d.ProxyKeyHash == nil ||
		subtle.ConstantTimeCompare(HashProxyKey(key[0]), d.ProxyKeyHash) != 1 {
		return Admission{}, ErrProxyRejected
	}
	if d.CustomClientIPHeader != "" {
		values := r.Header.Values(d.CustomClientIPHeader)
		if len(values) != 1 || strings.Contains(values[0], ",") {
			return Admission{}, ErrClientIP
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(values[0]))
		if err != nil || ip.Zone() != "" {
			return Admission{}, ErrClientIP
		}
		adm.ClientIP = ip.Unmap().String()
	}
	return adm, nil
}

// Middleware admits custom-domain requests before tenant resolution: it pins
// Host to the stored public domain, records the client IP and strips proxy
// and forwarding headers. Other hosts keep legacy forwarded-header trust only
// from permitted peers, and a forwarded host can never name a custom domain.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adm, err := s.Admit(r)
		if errors.Is(err, ErrNotCustomDomain) {
			s.legacy(w, r, next)
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		ip, _ := netip.ParseAddr(adm.ClientIP)
		r = r.WithContext(WithPublicDomain(httpx.WithClientIP(r.Context(), ip), adm.public))
		r.Host = adm.PublicHost
		for _, h := range forwarding {
			r.Header.Del(h)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Service) legacy(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if !s.cfg.Proxy.legacy(peerAddr(r)) {
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-For")
		next.ServeHTTP(w, r)
		return
	}
	if fwd := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fwd != "" {
		if host, err := hostname.NormalizeOperatorHost(fwd); err == nil {
			b, err := s.st.CustomDomains().GetHost(r.Context(), host)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				fail(w, err)
				return
			}
			if err == nil && (b.Kind == store.HostPublic || b.Kind == store.HostOrigin) {
				fail(w, ErrMisdirected)
				return
			}
		}
	}
	next.ServeHTTP(w, r)
}

func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, ErrUnknownHost):
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
	case errors.Is(err, ErrProxyRejected):
		httpx.WriteError(w, http.StatusForbidden, "access_denied", "proxy authentication failed")
	case errors.Is(err, ErrMisdirected):
		httpx.WriteError(w, http.StatusMisdirectedRequest, "invalid_request", "misdirected request")
	case errors.Is(err, ErrClientIP):
		httpx.WriteError(w, http.StatusBadRequest, "invalid_request", "invalid client IP header")
	default:
		httpx.WriteError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service unavailable")
	}
}
