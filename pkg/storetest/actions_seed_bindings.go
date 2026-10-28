package storetest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// ActionsSeedBindings exercises durable initialization and management ownership
// across every driver, including transactions, RPCs and plugin transports.
func ActionsSeedBindings(t *testing.T, factory Factory) {
	t.Helper()
	s := open(t, factory)
	ctx := context.Background()
	type initializer interface {
		BindingsInitialized(context.Context, string, string) (bool, error)
		InitializeBindings(context.Context, string, string, []store.Binding) ([]store.BoundVersion, error)
	}
	a, ok := s.Actions().(initializer)
	if !ok {
		t.Fatal("Actions store lacks atomic durable binding initialization")
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tid := range []string{"seed-a", "seed-b"} {
		must(s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
	}
	// Small immutable snapshots suffice here; npm and Node are not involved.
	must(s.Actions().PutBuild(ctx, &store.Build{TenantID: "seed-a", ID: "built", Status: store.BuildBuilt}))
	must(s.Actions().PutArtifact(ctx, "seed-a", "built", []byte("artifact")))
	mk := func(id string) {
		must(s.Actions().CreateAction(ctx, &store.Action{TenantID: "seed-a", ID: id, Name: id, Trigger: "post-login", Runtime: "node22", DraftBuildID: "built"}))
		_, err := s.Actions().Deploy(ctx, "seed-a", id, "")
		must(err)
	}
	mk("seed")
	mk("management")
	seed := []store.Binding{{ActionID: "seed", DisplayName: "seed"}}
	initialized := func(tid, trigger string, want bool) {
		t.Helper()
		got, err := a.BindingsInitialized(ctx, tid, trigger)
		must(err)
		if got != want {
			t.Fatalf("%s/%s initialized=%v want%v", tid, trigger, got, want)
		}
	}
	initialized("seed-a", "post-login", false)
	if _, err := a.InitializeBindings(ctx, "seed-a", "post-login", []store.Binding{{ActionID: "missing"}}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("invalid init=%v", err)
	}
	initialized("seed-a", "post-login", false)
	// Rollback represents a crash before transaction commit: both marker and
	// rows disappear, and the exact same seed can retry successfully.
	rollback := errors.New("rollback initialization")
	err := s.WithTx(ctx, func(tx store.Store) error {
		repo := tx.Actions().(initializer)
		if _, err := repo.InitializeBindings(ctx, "seed-a", "post-login", seed); err != nil {
			return err
		}
		v, err := repo.BindingsInitialized(ctx, "seed-a", "post-login")
		if err != nil {
			return err
		}
		if !v {
			return errors.New("marker absent inside tx")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatalf("rollback=%v", err)
	}
	initialized("seed-a", "post-login", false)
	bs, err := a.InitializeBindings(ctx, "seed-a", "post-login", seed)
	must(err)
	if len(bs) != 1 || bs[0].ActionID != "seed" {
		t.Fatalf("first initialization=%v", bs)
	}
	initialized("seed-a", "post-login", true)
	initialized("seed-b", "post-login", false)
	initialized("seed-a", "credentials-exchange", false)
	_, err = s.Actions().ReplaceBindings(ctx, "seed-a", "post-login", nil)
	must(err)
	for i := 0; i < 2; i++ {
		bs, err = a.InitializeBindings(ctx, "seed-a", "post-login", seed)
		must(err)
		if len(bs) != 0 {
			t.Fatal("seed reenabled explicitly empty bindings")
		}
	}
	// A management clear before the first seed also establishes ownership.
	_, err = s.Actions().ReplaceBindings(ctx, "seed-b", "post-login", nil)
	must(err)
	initialized("seed-b", "post-login", true)
	bs, err = a.InitializeBindings(ctx, "seed-b", "post-login", seed)
	must(err)
	if len(bs) != 0 {
		t.Fatal("initial empty management list overwritten")
	}
	// Rollback a management clear too: its marker cannot suppress later seed.
	err = s.WithTx(ctx, func(tx store.Store) error {
		if _, err := tx.Actions().ReplaceBindings(ctx, "seed-b", "credentials-exchange", nil); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	initialized("seed-b", "credentials-exchange", false)
	// Tenant deletion clears durable markers; tenant ID reuse starts fresh.
	must(s.Tenants().Delete(ctx, "seed-b"))
	must(s.Tenants().Create(ctx, &store.Tenant{ID: "seed-b", Name: "seed-b"}))
	initialized("seed-b", "post-login", false)
	// Each race uses a fresh tenant/trigger marker. Whichever writer starts
	// first, management always owns the final value and a seed retry preserves it.
	for i := 0; i < 8; i++ {
		tid := fmt.Sprintf("seed-race-%d", i)
		must(s.Tenants().Create(ctx, &store.Tenant{ID: tid, Name: tid}))
		must(s.Actions().PutBuild(ctx, &store.Build{TenantID: tid, ID: "built", Status: store.BuildBuilt}))
		must(s.Actions().PutArtifact(ctx, tid, "built", []byte("artifact")))
		for _, id := range []string{"seed", "management"} {
			must(s.Actions().CreateAction(ctx, &store.Action{TenantID: tid, ID: id, Name: id, Trigger: "post-login", Runtime: "node22", DraftBuildID: "built"}))
			_, err := s.Actions().Deploy(ctx, tid, id, "")
			must(err)
		}
		managed := []store.Binding{{ActionID: "management", DisplayName: "management"}}
		if i%2 == 0 {
			managed = nil
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, err := a.InitializeBindings(ctx, tid, "post-login", seed)
			errs <- err
		}()
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Actions().ReplaceBindings(ctx, tid, "post-login", managed)
			errs <- err
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			must(err)
		}
		initialized(tid, "post-login", true)
		got, err := s.Actions().Bindings(ctx, tid, "post-login")
		must(err)
		if len(got) != len(managed) || (len(got) > 0 && got[0].ActionID != "management") {
			t.Fatalf("concurrent seed overwrote management: %v", got)
		}
		if _, err := a.InitializeBindings(ctx, tid, "post-login", []store.Binding{{ActionID: "missing"}}); err != nil {
			t.Fatalf("initialized list still validates obsolete refs: %v", err)
		}
	}
	// Management edits (nonempty and empty) survive a seed after lock wait.
	for _, managed := range [][]store.Binding{{{ActionID: "management", DisplayName: "management"}}, nil} {
		_, err = s.Actions().ReplaceBindings(ctx, "seed-a", "post-login", managed)
		must(err)
		start := make(chan struct{})
		done := make(chan error, 1)
		go func() { <-start; _, err := a.InitializeBindings(ctx, "seed-a", "post-login", seed); done <- err }()
		close(start)
		must(<-done)
		got, err := s.Actions().Bindings(ctx, "seed-a", "post-login")
		must(err)
		if len(got) != len(managed) || (len(got) > 0 && got[0].ActionID != "management") {
			t.Fatal("seed overwrote management")
		}
	}
	// Forced deletion removes rows but retains trigger initialization.
	_, err = s.Actions().ReplaceBindings(ctx, "seed-a", "post-login", seed)
	must(err)
	must(s.Actions().DeleteAction(ctx, "seed-a", "seed", true))
	initialized("seed-a", "post-login", true)
	bs, err = a.InitializeBindings(ctx, "seed-a", "post-login", seed)
	must(err)
	if len(bs) != 0 {
		t.Fatal("force deletion lost initialization")
	}
	if _, err := a.BindingsInitialized(ctx, "missing", "post-login"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing tenant=%v", err)
	}
}
