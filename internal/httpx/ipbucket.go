package httpx

import "net/netip"

// IPBucket groups an address with its neighbours for per-source limits.
// An IPv6 host usually gets a whole /64, so one host could otherwise
// rotate through countless addresses: IPv6 addresses are bucketed by
// their /64 ("2001:db8:1:2::/64"). IPv4 addresses, and IPv4-mapped IPv6
// addresses, are returned as plain IPv4. Anything that does not parse is
// returned unchanged.
func IPBucket(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	p, err := addr.WithZone("").Prefix(64)
	if err != nil {
		return ip
	}
	return p.String()
}
