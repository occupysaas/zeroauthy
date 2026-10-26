// Package hostname provides shared hostname equivalence for registry writers.
package hostname

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

func NormalizeDNSName(raw string) (string, error) { return normalizeName(raw, true) }

// NormalizeOperatorHost retains local operator host/port support. Public API
// callers must use NormalizeDNSName, which never accepts ports or local names.
func NormalizeOperatorHost(raw string) (string, error) {
	if strings.Contains(raw, ":") {
		host, port, err := net.SplitHostPort(raw)
		n, e := strconv.Atoi(port)
		if err != nil || e != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid operator host port")
		}
		name, e := normalizeName(host, false)
		if e != nil {
			return "", e
		}
		return net.JoinHostPort(name, strconv.Itoa(n)), nil
	}
	return normalizeName(raw, false)
}

func normalizeName(raw string, public bool) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, ":/@\\*?#[]") {
		return "", errors.New("invalid DNS name")
	}
	ascii, err := idna.Lookup.ToASCII(raw)
	if err != nil {
		return "", errors.New("invalid IDNA name")
	}
	name := strings.ToLower(strings.TrimSuffix(ascii, "."))
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return "", errors.New("invalid DNS name length or IP address")
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("invalid DNS label")
			}
		}
	}
	if public {
		suffix, _ := publicsuffix.PublicSuffix(name)
		if len(labels) < 2 || name == suffix {
			return "", errors.New("DNS name must be below a public suffix")
		}
	}
	return name, nil
}
