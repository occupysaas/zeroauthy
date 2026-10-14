package login

import (
	"net"
	"net/http"
	"strings"
)

// clientIP is the address used for throttling. X-Forwarded-For is used
// only when the deployment trusts proxy headers, and then only its
// rightmost non-empty entry: that is the address the single trusted proxy
// appended. Earlier entries are client-supplied and trivially spoofed.
func clientIP(r *http.Request, trustProxy bool) string {
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
