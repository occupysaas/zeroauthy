package certificates

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
)

// ALPNProto is the TLS-ALPN-01 protocol (RFC 8737).
const ALPNProto = "acme-tls/1"

// alpnChallenge serves a challenge certificate only to an acme-tls/1
// handshake whose SNI has a live challenge. Ordinary handshakes never reach
// this path, and challenge handshakes never get an ordinary certificate.
func (m *Manager) alpnChallenge(ctx context.Context, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host, err := hostname.NormalizeDNSName(hello.ServerName)
	if err != nil {
		return nil, ErrNoCertificate
	}
	row, err := m.liveChallenge(ctx, "tls-alpn-01", host)
	if err != nil {
		return nil, fmt.Errorf("certificates: challenge store unavailable: %w", err)
	}
	if row == nil || row.PublicData.Identifier != host {
		return nil, ErrNoCertificate
	}
	keyPEM, err := m.Open(row.Kind, row.Key, row.TenantID, row.DomainID, row.Generation, row.Ciphertext)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(row.PublicData.CertificateChainPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func isALPNChallenge(hello *tls.ClientHelloInfo) bool {
	return slices.Contains(hello.SupportedProtos, ALPNProto)
}
