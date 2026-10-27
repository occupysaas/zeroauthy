// Package fixture supplies constructor-only local federation transport. The
// production public-address, HTTPS, certificate and issuer checks stay active.
package fixture

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/federation/script"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type publicAnswer struct{}

func (publicAnswer) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if !strings.HasSuffix(host, ".e2e.test") {
		return nil, fmt.Errorf("unexpected fixture lookup")
	}
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

// Network returns production-policy providers whose public fixture address
// dials address and whose Google and Microsoft endpoints live under
// https://idp.e2e.test.
func Network(roots *x509.CertPool, address string) *federation.Providers {
	policy := federation.NetworkPolicy{Resolver: publicAnswer{}, RootCAs: roots, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "8.8.8.8:443" {
			return nil, fmt.Errorf("unexpected fixture provider address")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	base := "https://idp.e2e.test"
	return federation.NewProviders(policy, nil).WithGoogleFixture(federation.GoogleOverride{Issuer: base + "/google", Endpoints: store.FederationEndpoints{AuthorizationURL: base + "/google/authorize", TokenURL: base + "/google/token", JWKSURL: base + "/google/jwks", TokenAuthMethod: "client_secret_post"}}).WithMicrosoftFixture(federation.MicrosoftOverride{AuthorityBaseURL: base})
}

// Providers is Network with a probed profile-script runner attached.
func Providers(roots *x509.CertPool, address string) (*federation.Providers, *script.Runner, error) {
	ps := Network(roots, address)
	r, err := script.NewRunner(script.Config{}, script.NewBroker(ps.HTTPClient()))
	if err != nil {
		return nil, nil, err
	}
	if err = r.Probe(); err != nil {
		r.Close()
		return nil, nil, fmt.Errorf("profile script runtime: %w", err)
	}
	return ps.WithScripts(r), r, nil
}
