package httpx

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP is the address used for throttling. X-Forwarded-For is used
// only when the deployment trusts proxy headers, and then only its
// rightmost non-empty entry: that is the address the single trusted proxy
// appended. Earlier entries are client-supplied and trivially spoofed.
func ClientIP(r *http.Request, trustProxy bool) string {
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
