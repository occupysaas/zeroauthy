package httpx

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// WithClientIP records the client address an authenticated proxy boundary
// established. It overrides every other source for the rest of the request,
// so throttling, logging and recorded addresses all share it.
func WithClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP is the address used for throttling: the one an authenticated
// proxy boundary established (WithClientIP), else X-Forwarded-For when the
// deployment trusts proxy headers, and then only its rightmost non-empty
// entry: that is the address the single trusted proxy appended. Earlier
// entries are client-supplied and trivially spoofed.
func ClientIP(r *http.Request, trustProxy bool) string {
	if ip, ok := r.Context().Value(clientIPKey{}).(netip.Addr); ok {
		return ip.String()
	}
	if trustProxy {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		for i := len(parts) - 1; i >= 0; i-- {
			if ip := strings.TrimSpace(parts[i]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// RecordedIP is ClientIP as stored on a session or a user's last_ip: the
// canonical form of the address without a zone, or "" when ClientIP is not
// an IP address (a hostile X-Forwarded-For). Stored text is shown by the
// Management API, so it must be an address and nothing else.
func RecordedIP(r *http.Request, trustProxy bool) string {
	return CanonicalIP(ClientIP(r, trustProxy))
}

// CanonicalIP is s parsed as an IP address, without a zone, in canonical
// form, or "" when s is not one.
func CanonicalIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.WithZone("").String()
}
