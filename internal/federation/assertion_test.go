package federation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"sync"
	"testing"
)

func TestAssertionShape(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{14}, 32))
	conn := &store.Connection{TenantID: "t", ID: "c", Name: "enterprise", Strategy: "oidc"}
	if e := st.Connections().Create(ctx, conn); e != nil {
		t.Fatal(e)
	}
	cfg := oidcConfig()
	cfg.AssertionAlg = "RS256"
	seen := map[string]bool{}
	for range 2 {
		raw, e := ClientAssertion(ctx, st, w, conn, cfg, "https://provider.example", fixedTime)
		if e != nil {
			t.Fatal(e)
		}
		obj, e := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
		if e != nil {
			t.Fatal(e)
		}
		list, e := st.ConnectionKeys().List(ctx, "t", "c")
		if e != nil {
			t.Fatal(e)
		}
		cert, e := x509.ParseCertificate(list[0].CertDER)
		if e != nil {
			t.Fatal(e)
		}
		b, e := obj.Verify(cert.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		var c map[string]any
		if e := json.Unmarshal(b, &c); e != nil {
			t.Fatal(e)
		}
		if c["iss"] != "client" || c["sub"] != "client" || c["aud"] != "https://provider.example" || c["exp"].(float64)-c["iat"].(float64) != 60 || obj.Signatures[0].Header.KeyID != list[0].KID || seen[c["jti"].(string)] {
			t.Fatal(c)
		}
		seen[c["jti"].(string)] = true
	}
}
func TestTokenRequestNoSecretWithAssertion(t *testing.T) {
	p := newIDP(t)
	ps := p.providers()
	in := p.exchangeInput(t, ps)
	in.Endpoints.TokenAuthMethod = "private_key_jwt"
	in.ClientAssertion = func(aud string) (string, error) { return "throwaway-assertion", nil }
	if _, e := ps.For(in.Config).Exchange(context.Background(), in); e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.forms[0].Get("client_secret") != "" || p.forms[0].Get("client_assertion") != "throwaway-assertion" {
		t.Fatal("incorrect client authentication")
	}
}

func TestAssertionUsesCurrentKey(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{15}, 32))
	conn := &store.Connection{TenantID: "t", ID: "c", Name: "enterprise", Strategy: "oidc"}
	if e := s.Connections().Create(ctx, conn); e != nil {
		t.Fatal(e)
	}
	cfg := oidcConfig()
	cfg.AssertionAlg = "ES256"
	if _, e := ClientAssertion(ctx, s, w, conn, cfg, "https://provider.example", fixedTime); e != nil {
		t.Fatal(e)
	}
	next, e := GenerateConnectionKey(w, conn, "signing", "ES256", "login.example", fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	current, e := s.ConnectionKeys().Rotate(ctx, "t", "c", "signing", next, fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := ClientAssertion(ctx, s, w, conn, cfg, "https://provider.example", fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	obj, e := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if e != nil || obj.Signatures[0].Header.KeyID != current.KID {
		t.Fatal("old key used", e)
	}
}
func TestAssertionLazyKey(t *testing.T) {
	ctx := context.Background()
	s := memory.New()
	w, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{16}, 32))
	conn := &store.Connection{TenantID: "t", ID: "c", Name: "enterprise", Strategy: "oidc"}
	if e := s.Connections().Create(ctx, conn); e != nil {
		t.Fatal(e)
	}
	cfg := oidcConfig()
	cfg.AssertionAlg = "ES256"
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			_, e := ClientAssertion(ctx, s, w, conn, cfg, "https://provider.example", fixedTime)
			errs <- e
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	list, e := s.ConnectionKeys().List(ctx, "t", "c")
	if e != nil || len(list) != 2 {
		t.Fatal(list, e)
	}
}
