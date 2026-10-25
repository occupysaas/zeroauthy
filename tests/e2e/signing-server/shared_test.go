package main

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func openStore(t *testing.T, ctx context.Context, dsn string) store.Store {
	t.Helper()
	st, err := storage.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestM20TwoInstancesRestart(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "m20-shared.db")
	a := openStore(t, ctx, dsn)
	if err := a.(storage.Migrator).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Tenants().Create(ctx, &store.Tenant{ID: "m20", Name: "m20"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ma := keys.NewManager(a.SigningKeys(), w)
	if err = ma.Ensure(ctx, "m20"); err != nil {
		t.Fatal(err)
	}
	old, err := ma.Sign(ctx, "m20", map[string]any{"sub": "old"})
	if err != nil {
		t.Fatal(err)
	}
	oldKeys, err := a.SigningKeys().List(ctx, "m20")
	if err != nil {
		t.Fatal(err)
	}
	oldKid := ""
	for _, k := range oldKeys {
		if k.Status == store.KeyCurrent {
			oldKid = k.KID
		}
	}
	b := openStore(t, ctx, dsn)
	defer b.Close()
	mb := keys.NewManager(b.SigningKeys(), w)
	var claims map[string]any
	if err = mb.Verify(ctx, "m20", old, &claims); err != nil {
		t.Fatalf("second process rejected current token: %v", err)
	}
	rot, err := ma.RotateWithResult(ctx, "m20")
	if err != nil {
		t.Fatal(err)
	}
	if err = mb.Verify(ctx, "m20", old, &claims); err != nil {
		t.Fatalf("previous token was not retained: %v", err)
	}
	if _, err = mb.Revoke(ctx, "m20", oldKid); err != nil {
		t.Fatal(err)
	}
	if err = ma.Verify(ctx, "m20", old, &claims); err == nil {
		t.Fatal("revoked key remained trusted in the first process")
	}
	newToken, err := mb.Sign(ctx, "m20", map[string]any{"sub": "new"})
	if err != nil {
		t.Fatal(err)
	}
	current, err := a.SigningKeys().Get(ctx, "m20", rot.Current.KID)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	c := openStore(t, ctx, dsn)
	defer c.Close()
	mc := keys.NewManager(c.SigningKeys(), w)
	if err = mc.Ensure(ctx, "m20"); err != nil {
		t.Fatal(err)
	}
	restarted, err := c.SigningKeys().Get(ctx, "m20", rot.Current.KID)
	if err != nil {
		t.Fatal(err)
	}
	if string(current.CertificateDER) != string(restarted.CertificateDER) || !current.CreatedAt.Equal(restarted.CreatedAt) {
		t.Fatal("restart changed certificate bytes or timestamp")
	}
	if err = mc.Verify(ctx, "m20", newToken, &claims); err != nil {
		t.Fatalf("restart rejected current token: %v", err)
	}
}

func TestM20ConcurrentRotateRevoke(t *testing.T) {
	ctx := context.Background()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "m20-concurrent.db")
	a := openStore(t, ctx, dsn)
	defer a.Close()
	if err := a.(storage.Migrator).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	b := openStore(t, ctx, dsn)
	defer b.Close()
	if err := a.Tenants().Create(ctx, &store.Tenant{ID: "m20", Name: "m20"}); err != nil {
		t.Fatal(err)
	}
	w, err := keys.NewLocalWrapper(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ma, mb := keys.NewManager(a.SigningKeys(), w), keys.NewManager(b.SigningKeys(), w)
	if err = ma.Ensure(ctx, "m20"); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	type outcome struct {
		r   *store.SigningKeyRotation
		err error
	}
	out := make(chan outcome, 2)
	var wg sync.WaitGroup
	for _, m := range []*keys.Manager{ma, mb} {
		wg.Add(1)
		go func(m *keys.Manager) {
			defer wg.Done()
			<-start
			r, e := m.RotateWithResult(ctx, "m20")
			out <- outcome{r, e}
		}(m)
	}
	close(start)
	wg.Wait()
	close(out)
	seen := map[string]bool{}
	for x := range out {
		if x.err != nil || x.r == nil || x.r.Current == nil {
			t.Fatalf("rotation result: %+v", x)
		}
		if seen[x.r.Current.KID] {
			t.Fatal("rotations returned a shared result")
		}
		seen[x.r.Current.KID] = true
	}
	all, err := a.SigningKeys().List(ctx, "m20")
	if err != nil {
		t.Fatal(err)
	}
	curr, next := 0, 0
	var previous string
	for _, k := range all {
		if k.Status == store.KeyCurrent {
			curr++
		}
		if k.Status == store.KeyNext {
			next++
		}
		if k.Status == store.KeyPrevious {
			previous = k.KID
		}
	}
	if curr != 1 || next != 1 || previous == "" {
		t.Fatalf("unexpected post-rotation state current=%d next=%d previous=%q", curr, next, previous)
	}
	// Race a further rotation against revocation of an already previous key.
	// Each SQL handle must observe the committed result without losing either
	// mutation or introducing a second current/next key.
	errs := make(chan error, 2)
	go func() { _, err := ma.RotateWithResult(ctx, "m20"); errs <- err }()
	go func() { _, err := mb.Revoke(ctx, "m20", previous); errs <- err }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	revoked, err := a.SigningKeys().Get(ctx, "m20", previous)
	if err != nil || revoked.Status != store.KeyRevoked {
		t.Fatal("concurrent rotation lost revocation")
	}
	all, err = a.SigningKeys().List(ctx, "m20")
	if err != nil {
		t.Fatal(err)
	}
	curr, next = 0, 0
	for _, key := range all {
		if key.Status == store.KeyCurrent {
			curr++
		}
		if key.Status == store.KeyNext {
			next++
		}
	}
	if curr != 1 || next != 1 {
		t.Fatal("concurrent rotate/revoke broke current/next uniqueness")
	}

}
