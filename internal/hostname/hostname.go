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

// NormalizeOperatorHost retains privileged local/IP aliases and host/port
// support. It collapses the HTTPS default port, including bracketed IPv6 forms.
// Public API callers must use NormalizeDNSName, which rejects ports and IPs.
func NormalizeOperatorHost(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "/@\\*?#") {
		return "", errors.New("invalid operator host")
	}
	host, port := raw, ""
	bracketed := strings.HasPrefix(raw, "[")
	if bracketed && strings.HasSuffix(raw, "]") {
		host = raw[1 : len(raw)-1]
	} else if strings.Contains(raw, ":") {
		var err error
		host, port, err = net.SplitHostPort(raw)
		if err != nil {
			return "", errors.New("invalid operator host port")
		}
	}
	ip := net.ParseIP(host)
	if bracketed && ip == nil {
		return "", errors.New("invalid operator IP literal")
	}
	if port != "" {
		for _, ch := range port {
			if ch < '0' || ch > '9' {
				return "", errors.New("invalid operator host port")
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid operator host port")
		}
		port = strconv.Itoa(n)
	}
	var name string
	if ip != nil {
		name = ip.String()
	} else {
		var err error
		name, err = normalizeName(host, false)
		if err != nil {
			return "", err
		}
	}
	if port == "" || port == "443" {
		if strings.Contains(name, ":") {
			return "[" + name + "]", nil
		}
		return name, nil
	}
	return net.JoinHostPort(name, port), nil
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
