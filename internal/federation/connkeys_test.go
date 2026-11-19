package federation

import (
	"bytes"
	"context"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"sync"
	"testing"
)

func TestConnectionKeySealing(t *testing.T) {
	w, e := keys.NewLocalWrapper(bytes.Repeat([]byte{11}, 32))
	if e != nil {
		t.Fatal(e)
	}
	c := &store.Connection{TenantID: "t", ID: "c"}
	k, e := GenerateConnectionKey(w, c, "signing", "ES384", "login.example", fixedTime)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := OpenConnectionKey(w, k); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*store.ConnectionKey){func(k *store.ConnectionKey) { k.TenantID = "other" }, func(k *store.ConnectionKey) { k.ConnectionID = "other" }, func(k *store.ConnectionKey) { k.Use = "encryption" }, func(k *store.ConnectionKey) { k.KID = "other" }, func(k *store.ConnectionKey) { k.Alg = "ES256" }} {
		n := k.Clone()
		mutate(n)
		if _, e := OpenConnectionKey(w, n); e == nil {
			t.Fatal("rebound private key accepted")
		}
	}
}
func TestEnsureKeysConcurrent(t *testing.T) {
	w, e := keys.NewLocalWrapper(bytes.Repeat([]byte{12}, 32))
	if e != nil {
		t.Fatal(e)
	}
	s := memory.New()
	ctx := context.Background()
	c := &store.Connection{TenantID: "t", ID: "c", Name: "enterprise", Strategy: "oidc"}
	if e := s.Connections().Create(ctx, c); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, e := EnsureKeys(ctx, s, w, c, "signing", "ES256", "login.example", fixedTime); errs <- e })
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
