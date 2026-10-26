package certificates

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"

	"golang.org/x/crypto/acme"

	"github.com/zeroauthy/zeroauthy/internal/hostname"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const challengePrefix = "/.well-known/acme-challenge/"

func challengeKey(typ, id string) string { return "challenge/" + typ + "/" + id }

// challengeRecord builds the shared record any replica answers from: the
// HTTP-01 key authorization is public; the TLS-ALPN-01 key is sealed.
func (w *Worker) challengeRecord(acct crypto.Signer, d *store.CustomDomain, chal *acme.Challenge, identifier string) (*store.TLSAsset, error) {
	row := &store.TLSAsset{Kind: store.TLSAssetChallenge, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation,
		ExpiresAt:  w.m.clock().Add(recordTTL),
		PublicData: store.TLSPublicData{Version: PublicDataVersion, ChallengeType: chal.Type, Identifier: identifier, Token: chal.Token}}
	switch chal.Type {
	case "http-01":
		ka, err := w.ca.HTTP01(acct, chal.Token)
		if err != nil {
			return nil, err
		}
		row.Key, row.PublicData.KeyAuthorization = challengeKey("http-01", chal.Token), ka
	case "tls-alpn-01":
		cert, err := w.ca.TLSALPN01(acct, chal.Token, identifier)
		if err != nil {
			return nil, err
		}
		row.Key = challengeKey("tls-alpn-01", identifier)
		if err := w.m.sealChallengeCert(row, cert.Certificate, cert.PrivateKey); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("certificates: unsupported challenge")
	}
	return row, nil
}

func (m *Manager) sealChallengeCert(row *store.TLSAsset, chain [][]byte, key crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if row.Ciphertext, err = m.Seal(row.Kind, row.Key, row.TenantID, row.DomainID, row.Generation, keyPEM); err != nil {
		return err
	}
	for _, c := range chain {
		row.PublicData.CertificateChainPEM = append(row.PublicData.CertificateChainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	return nil
}

// liveChallenge returns an unexpired challenge record of typ, or nil.
func (m *Manager) liveChallenge(ctx context.Context, typ, id string) (*store.TLSAsset, error) {
	row, err := m.st.TLSAssets().Get(ctx, challengeKey(typ, id))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if row.Kind != store.TLSAssetChallenge || row.PublicData.Version != PublicDataVersion || row.PublicData.ChallengeType != typ ||
		!m.clock().Before(row.ExpiresAt) {
		return nil, nil
	}
	return row, nil
}

// HTTPHandler serves the plain-HTTP listener: exact live HTTP-01 challenges
// for their own host (GET/HEAD), and otherwise a GET/HEAD redirect to HTTPS
// only for an active registered browser host. Unknown hosts and tokens are
// 404, unsafe methods 405; no request content ever chooses another host.
// A non-nil next handles non-challenge traffic instead of the redirect.
func (m *Manager) HTTPHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		safe := r.Method == http.MethodGet || r.Method == http.MethodHead
		host, herr := hostname.NormalizeOperatorHost(r.Host)
		if herr == nil {
			if h, _, err := splitPort(host); err == nil {
				host = h
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), handshakeBudget)
		defer cancel()
		if token, ok := strings.CutPrefix(r.URL.Path, challengePrefix); ok {
			if !safe {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			row, err := m.liveChallenge(ctx, "http-01", token)
			switch {
			case err != nil:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			case row == nil || herr != nil || row.PublicData.Identifier != host || strings.Contains(token, "/"):
				http.NotFound(w, r)
			default:
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(row.PublicData.KeyAuthorization))
			}
			return
		}
		if next != nil {
			next.ServeHTTP(w, r)
			return
		}
		if !safe {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if herr != nil {
			http.NotFound(w, r)
			return
		}
		b, err := m.st.CustomDomains().GetHost(ctx, host)
		if err != nil || !b.Active || b.Kind == store.HostOrigin {
			http.NotFound(w, r)
			return
		}
		// RequestURI keeps the client's escaping; it is always path-absolute
		// here, and the Location host is the registered one.
		uri := r.URL.RequestURI()
		if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
			uri = "/"
		}
		http.Redirect(w, r, "https://"+b.Host+uri, http.StatusPermanentRedirect)
	})
}

func splitPort(host string) (string, string, error) {
	i := strings.LastIndexByte(host, ':')
	if i < 0 || strings.HasSuffix(host, "]") {
		return host, "", nil
	}
	return host[:i], host[i+1:], nil
}
