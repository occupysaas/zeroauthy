package adhub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// env is a memory store with two tenants, each with an ad connection
// provisioned by the service.
type env struct {
	t     *testing.T
	st    store.Store
	svc   *Service
	ta    *store.Tenant
	tb    *store.Tenant
	conn  *store.Connection
	connB *store.Connection
	now   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	w, err := keys.NewLocalWrapper(bytes.Repeat([]byte{38}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: memory.New(), now: time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)}
	e.svc = &Service{Store: e.st, Wrapper: w, Now: func() time.Time { return e.now }}
	ctx := context.Background()
	e.ta = &store.Tenant{ID: "ten_a", Name: "acme", Domains: []string{"acme.example.test"}, CanonicalHost: "acme.example.test"}
	e.tb = &store.Tenant{ID: "ten_b", Name: "beta", Domains: []string{"beta.example.test"}, CanonicalHost: "beta.example.test"}
	for _, tn := range []*store.Tenant{e.ta, e.tb} {
		if err := e.st.Tenants().Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
	}
	e.conn = e.adConnection(e.ta, "con_corp000000000001", "corp")
	e.connB = e.adConnection(e.tb, "con_corp000000000002", "corp")
	return e
}

func (e *env) adConnection(tn *store.Tenant, id, name string) *store.Connection {
	e.t.Helper()
	ctx := context.Background()
	c := &store.Connection{TenantID: tn.ID, ID: id, Name: name, Strategy: store.StrategyAD, Extra: map[string]any{"tenant_domain": "corp.example.test"}}
	err := e.st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Connections().Create(ctx, c); err != nil {
			return err
		}
		return e.svc.Provision(ctx, tx, c)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

// ticket returns the ticket of conn.
func (e *env) ticket(tn *store.Tenant, conn *store.Connection) string {
	e.t.Helper()
	u, err := e.svc.TicketURL(context.Background(), tn.CanonicalHost, conn)
	if err != nil {
		e.t.Fatal(err)
	}
	prefix := "https://" + tn.CanonicalHost + TicketPrefix
	if !strings.HasPrefix(u, prefix) {
		e.t.Fatalf("ticket URL %s", u)
	}
	return strings.TrimPrefix(u, prefix)
}

// request is r addressed to tn's canonical host.
func request(tn *store.Tenant, method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, "https://"+tn.CanonicalHost+path, strings.NewReader(body))
	return r.WithContext(tenant.WithResolved(r.Context(), tenant.Resolved{Tenant: tn, Host: tn.CanonicalHost}))
}

// connectorKey is a throwaway connector key and its self-signed certificate.
type connectorKey struct {
	key *rsa.PrivateKey
	der []byte
}

func newConnectorKey(t *testing.T, bits int) connectorKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "corp"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return connectorKey{key: key, der: der}
}

func (k connectorKey) b64() string { return base64.StdEncoding.EncodeToString(k.der) }
