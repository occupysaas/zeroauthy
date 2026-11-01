package httpx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
)

// ErrBlockedAddress contains no endpoint or resolver diagnostics.
var ErrBlockedAddress = errors.New("blocked_address")

type ipResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type dialContext func(context.Context, string, string) (net.Conn, error)

// GuardedDialer resolves at each connection, rejects the entire answer set if
// any address violates policy, then dials only those checked IPs. The original
// HTTP URL remains intact for Host and TLS SNI/certificate verification.
func GuardedDialer(allowPrivate bool) func(context.Context, string, string) (net.Conn, error) {
	return guardedDialer(allowPrivate, net.DefaultResolver, (&net.Dialer{Timeout: 10 * time.Second}).DialContext)
}
func guardedDialer(allowPrivate bool, resolver ipResolver, dial dialContext) dialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, ErrBlockedAddress
		}
		var answers []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			answers = []netip.Addr{ip}
		} else {
			answers, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
		}
		if len(answers) == 0 {
			return nil, &net.DNSError{IsNotFound: true}
		}
		for _, ip := range answers {
			if !ip.IsValid() || (!allowPrivate && !rules.PublicAddr(ip)) {
				return nil, ErrBlockedAddress
			}
		}
		var last error
		for _, ip := range answers {
			conn, err := dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}
}
