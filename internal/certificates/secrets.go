package certificates

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// HostedWildcardKey is the deployment asset holding base_domain and
// *.base_domain; it has no tenant or domain owner.
const HostedWildcardKey = "hosted-wildcard"

// aadVersion is part of every AAD so a later format cannot open older bytes
// under a different interpretation.
const aadVersion = "zeroauthy-tls-asset/v1"

// Config is deployment TLS policy.
type Config struct {
	// DeploymentID and DirectoryURL bind every sealed asset: replicas of one
	// deployment share them; staging and production never do.
	DeploymentID, DirectoryURL string
	// BaseDomain bounds hosted wildcard eligibility (one label below it).
	BaseDomain string
	// HostedWildcard serves the hosted wildcard asset when it exists.
	HostedWildcard bool
	// Static are operator certificates (server.tls_cert_file); they serve
	// only registered hosts their SANs cover.
	Static []tls.Certificate
}

// Manager seals TLS material and selects certificates for handshakes. A
// handshake performs bounded store reads only: no DNS, order or provider call.
type Manager struct {
	st     store.Store
	w      keys.Wrapper
	cfg    Config
	clock  func() time.Time
	static []staticCert

	mu    sync.Mutex
	cache map[string]cached // asset key → parsed certificate at a revision
}

func NewManager(st store.Store, w keys.Wrapper, cfg Config, clock func() time.Time) (*Manager, error) {
	if cfg.DeploymentID == "" || cfg.DirectoryURL == "" {
		return nil, errors.New("certificates: a deployment ID and ACME directory URL are required")
	}
	m := &Manager{st: st, w: w, cfg: cfg, clock: clock, cache: map[string]cached{}}
	for i := range cfg.Static {
		s, err := parseStatic(&cfg.Static[i])
		if err != nil {
			return nil, err
		}
		m.static = append(m.static, s)
	}
	return m, nil
}

// aad length-prefixes every field, so no two bindings share an encoding.
func (m *Manager) aad(kind, key, tenantID, domainID string, generation int64) []byte {
	var out []byte
	for _, f := range []string{aadVersion, m.cfg.DeploymentID, m.cfg.DirectoryURL, kind, key, tenantID, domainID, strconv.FormatInt(generation, 10)} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// Seal encrypts private TLS material bound to its deployment, directory,
// record kind/key and tenant/domain generation.
func (m *Manager) Seal(kind, key, tenantID, domainID string, generation int64, plaintext []byte) ([]byte, error) {
	return m.w.Wrap(plaintext, m.aad(kind, key, tenantID, domainID, generation))
}

// Open is the inverse of Seal. A failure is never a reason to replace the
// stored material: callers must surface it (wrong master key, deployment or
// directory) rather than order new state.
func (m *Manager) Open(kind, key, tenantID, domainID string, generation int64, sealed []byte) ([]byte, error) {
	out, err := m.w.Unwrap(sealed, m.aad(kind, key, tenantID, domainID, generation))
	if err != nil {
		return nil, fmt.Errorf("certificates: cannot open %s %q: %w", kind, key, err)
	}
	return out, nil
}
