// Package tenant maps incoming requests to tenants.
package tenant

import (
	"net"
	"strings"
)

// NormalizeHost canonicalizes a Host header value: lowercase, no trailing
// dot, and no port when the port is the HTTPS default (443). Stored tenant
// domains use the same form.
func NormalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	name, port, err := net.SplitHostPort(h)
	if err != nil {
		// No port present.
		return strings.TrimSuffix(h, ".")
	}
	name = strings.TrimSuffix(name, ".")
	if port == "" || port == "443" {
		if strings.Contains(name, ":") {
			return "[" + name + "]" // IPv6 literal
		}
		return name
	}
	return net.JoinHostPort(name, port)
}
