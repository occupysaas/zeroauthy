package certificates

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
)

// CA is the subset of ACME the worker drives. Production uses NewACMECA over
// golang.org/x/crypto/acme; every call is authenticated by the account key
// and, once registered, its account URL.
type CA interface {
	Register(ctx context.Context, key crypto.Signer, email string) (accountURL string, err error)
	NewOrder(ctx context.Context, key crypto.Signer, accountURL string, names []string) (*acme.Order, error)
	Order(ctx context.Context, key crypto.Signer, accountURL, url string) (*acme.Order, error)
	Authorization(ctx context.Context, key crypto.Signer, accountURL, url string) (*acme.Authorization, error)
	Accept(ctx context.Context, key crypto.Signer, accountURL string, chal *acme.Challenge) error
	Finalize(ctx context.Context, key crypto.Signer, accountURL, finalizeURL string, csr []byte) (chain [][]byte, err error)
	HTTP01(key crypto.Signer, token string) (string, error)
	TLSALPN01(key crypto.Signer, token, identifier string) (tls.Certificate, error)
	DNS01(key crypto.Signer, token string) (string, error)
}

// acmeCA talks to one deployment-configured directory. Request content never
// changes the directory, and CA error bodies stay out of public messages.
type acmeCA struct {
	directory string
	http      *http.Client
}

// NewACMECA uses roots (the CA bundle) in addition to nothing else: when
// roots is nil the system pool applies. Validation is never disabled.
func NewACMECA(directoryURL string, roots *x509.CertPool) CA {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	if roots != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}
	return &acmeCA{directory: directoryURL, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

func (c *acmeCA) client(key crypto.Signer, accountURL string) *acme.Client {
	return &acme.Client{Key: key, DirectoryURL: c.directory, HTTPClient: c.http, KID: acme.KeyID(accountURL), UserAgent: "zeroauthy"}
}

func (c *acmeCA) Register(ctx context.Context, key crypto.Signer, email string) (string, error) {
	cl := c.client(key, "")
	acct, err := cl.Register(ctx, &acme.Account{Contact: []string{"mailto:" + email}}, acme.AcceptTOS)
	if errors.Is(err, acme.ErrAccountAlreadyExists) {
		acct, err = cl.GetReg(ctx, "")
	}
	if err != nil {
		return "", err
	}
	return acct.URI, nil
}

func (c *acmeCA) NewOrder(ctx context.Context, key crypto.Signer, accountURL string, names []string) (*acme.Order, error) {
	return c.client(key, accountURL).AuthorizeOrder(ctx, acme.DomainIDs(names...))
}

func (c *acmeCA) Order(ctx context.Context, key crypto.Signer, accountURL, url string) (*acme.Order, error) {
	return c.client(key, accountURL).GetOrder(ctx, url)
}

func (c *acmeCA) Authorization(ctx context.Context, key crypto.Signer, accountURL, url string) (*acme.Authorization, error) {
	return c.client(key, accountURL).GetAuthorization(ctx, url)
}

func (c *acmeCA) Accept(ctx context.Context, key crypto.Signer, accountURL string, chal *acme.Challenge) error {
	_, err := c.client(key, accountURL).Accept(ctx, chal)
	return err
}

func (c *acmeCA) Finalize(ctx context.Context, key crypto.Signer, accountURL, finalizeURL string, csr []byte) ([][]byte, error) {
	der, _, err := c.client(key, accountURL).CreateOrderCert(ctx, finalizeURL, csr, true)
	return der, err
}

func (c *acmeCA) HTTP01(key crypto.Signer, token string) (string, error) {
	return c.client(key, "").HTTP01ChallengeResponse(token)
}

func (c *acmeCA) TLSALPN01(key crypto.Signer, token, identifier string) (tls.Certificate, error) {
	return c.client(key, "").TLSALPN01ChallengeCert(token, identifier)
}

func (c *acmeCA) DNS01(key crypto.Signer, token string) (string, error) {
	return c.client(key, "").DNS01ChallengeRecord(token)
}
