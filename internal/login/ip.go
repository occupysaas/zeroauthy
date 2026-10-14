package login

import (
	"net"
	"net/http"
	"strings"
)

// clientIP is the address used for throttling. X-Forwarded-For is used
// only when the deployment trusts proxy headers.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			return strings.TrimSpace(strings.Split(fwd, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
