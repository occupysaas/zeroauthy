package providers

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var deniedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("ff00::/8"),
}

func isPublicAddress(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range deniedRanges {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func resolvedAddressesAllowed(ips []net.IPAddr, allowPrivate bool) bool {
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !allowPrivate && !isPublicAddress(ip.IP.String()) {
			return false
		}
	}
	return true
}

type policyDialer struct {
	resolver *net.Resolver
	timeout  time.Duration
	allow    map[string]bool
}

func newPolicyDialer(allowlist []string) *policyDialer {
	allow := map[string]bool{}
	for _, item := range allowlist {
		allow[strings.ToLower(strings.TrimSpace(item))] = true
	}
	return &policyDialer{resolver: net.DefaultResolver, timeout: 10 * time.Second, allow: allow}
}
func (d *policyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("email provider: invalid outbound address")
	}
	ips, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("email provider: outbound host lookup failed")
	}
	localOK := d.allow[strings.ToLower(net.JoinHostPort(host, port))]
	if !resolvedAddressesAllowed(ips, localOK) {
		return nil, errors.New("email provider: outbound address is not allowed")
	}
	var last error
	dial := net.Dialer{Timeout: d.timeout}
	for _, a := range ips {
		conn, e := dial.DialContext(ctx, network, net.JoinHostPort(a.IP.String(), port))
		if e == nil {
			return conn, nil
		}
		last = e
	}
	_ = last
	return nil, errors.New("email provider: outbound connection failed")
}
func portString(n int) string { return strconv.Itoa(n) }
