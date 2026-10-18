package grpcstore

import (
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

func tenantPB(id string) *storev1.Tenant {
	pb, _ := tenantToPB(&store.Tenant{ID: id, Name: id})
	return pb
}

func TestServerDomainErrorsInResponse(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	res, err := srv.TenantsGet(ctx, &storev1.TenantsGetRequest{Key: "missing"})
	if err != nil {
		t.Fatalf("transport error %v; domain errors belong in the response", err)
	}
	if res.GetError().GetKind() != storev1.Error_KIND_NOT_FOUND {
		t.Fatalf("error = %v, want NOT_FOUND", res.GetError())
	}
}

// A request without a value is a domain error, not a nil pointer.
func TestServerWriteWithoutValueIsAnError(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	up, err := srv.UserGrantsUpsert(ctx, &storev1.UserGrantWrite{})
	if err != nil || up.GetError() == nil || up.GetValue() != nil {
		t.Fatalf("UserGrantsUpsert = %v, %v; want an error in the response", up, err)
	}
	cr, err := srv.ClientGrantsCreate(ctx, &storev1.ClientGrantWrite{})
	if err != nil || cr.GetError() == nil {
		t.Fatalf("ClientGrantsCreate = %v, %v; want an error in the response", cr, err)
	}
}

// A host from before Plan 9 sends a client grant without subject_type: the
// server stores it as a client grant.
func TestServerClientGrantEmptySubjectTypeIsClient(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	res, err := srv.ClientGrantsCreate(ctx, &storev1.ClientGrantWrite{Value: &storev1.ClientGrant{
		TenantId: "t", Id: "g", ClientId: "c", Audience: "a", CreatedAt: tsToPB(time.Unix(0, 0))}})
	if err != nil || res.GetError() != nil {
		t.Fatalf("create = %v, %v", res, err)
	}
	got, err := srv.ClientGrantsFind(ctx, &storev1.ClientGrantsFindRequest{TenantId: "t", ClientId: "c", Audience: "a", SubjectType: store.SubjectTypeClient})
	if err != nil || got.GetError() != nil || got.GetValue().GetSubjectType() != store.SubjectTypeClient {
		t.Fatalf("find = %v, %v", got, err)
	}
}

func TestServerTxCommitAndRollback(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	defer srv.Close()

	begin := func(parent string) string {
		r, err := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: parent})
		if err != nil || r.Error != nil {
			t.Fatalf("BeginTx: %v %v", err, r.GetError())
		}
		return r.TxId
	}
	create := func(tx, id string) {
		r, err := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: tx, Value: tenantPB(id)})
		if err != nil || r.Error != nil {
			t.Fatalf("create %s: %v %v", id, err, r.GetError())
		}
	}

	tx := begin("")
	create(tx, "committed")
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: tx}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if _, err := mem.Tenants().Get(ctx, "committed"); err != nil {
		t.Fatal("committed write missing")
	}

	tx = begin("")
	create(tx, "outer")
	inner := begin(tx)
	create(inner, "inner")
	srv.Rollback(ctx, &storev1.EndTxRequest{TxId: inner}) // inner only
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: tx}); r.Error != nil {
		t.Fatal(r.Error)
	}
	if _, err := mem.Tenants().Get(ctx, "outer"); err != nil {
		t.Fatal("outer write lost")
	}
	if _, err := mem.Tenants().Get(ctx, "inner"); err == nil {
		t.Fatal("rolled-back inner write persisted")
	}
}

func TestServerUnknownTxIsAnError(t *testing.T) {
	srv := NewServer(memory.New())
	defer srv.Close()
	r, err := srv.TenantsCreate(context.Background(), &storev1.TenantWrite{TxId: "nope", Value: tenantPB("a")})
	if err != nil {
		t.Fatal(err)
	}
	if r.GetError() == nil || r.GetError().Kind != storev1.Error_KIND_UNSPECIFIED {
		t.Fatalf("error = %v, want an unknown-transaction error", r.GetError())
	}
}

// An abandoned transaction is rolled back after the idle timeout and its
// locks are released (memory's txMu), so a later transaction can proceed.
func TestServerAbandonedTxIsRolledBack(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem, WithTxIdleTimeout(50*time.Millisecond))
	defer srv.Close()
	r, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: r.TxId, Value: tenantPB("abandoned")})

	done := make(chan error, 1)
	go func() { done <- mem.WithTx(ctx, func(store.Store) error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned transaction never released")
	}
	if _, err := mem.Tenants().Get(ctx, "abandoned"); err == nil {
		t.Fatal("abandoned write persisted")
	}
	if c, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: r.TxId}); c.GetError() == nil {
		t.Fatal("Commit of an expired transaction succeeded")
	}
}

func TestServerCommitWithOpenChildFails(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	c, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() == nil {
		t.Fatal("parent committed while a child was open")
	}
	srv.Rollback(ctx, &storev1.EndTxRequest{TxId: c.TxId})
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() != nil {
		t.Fatal(r.GetError())
	}
}

// testStores returns fresh stores for the registry tests that depend on
// the driver's nesting: memory (snapshots) and sqlstore on SQLite
// (savepoints).
func testStores(t *testing.T) map[string]func(t *testing.T) store.Store {
	return map[string]func(t *testing.T) store.Store{
		"memory": func(*testing.T) store.Store { return memory.New() },
		"sqlite": func(t *testing.T) store.Store {
			ctx := context.Background()
			st, err := sqlstore.Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "z.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = st.Close() })
			if err := st.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			return st
		},
	}
}

func eachStore(t *testing.T, f func(t *testing.T, st store.Store)) {
	for name, mk := range testStores(t) {
		t.Run(name, func(t *testing.T) { f(t, mk(t)) })
	}
}

func isErr(e *storev1.Error, want error) bool {
	return e != nil && e.Kind == storev1.Error_KIND_UNSPECIFIED && e.Message == want.Error()
}

// stackFixture is a server over st with helpers that fail the test on
// unexpected errors.
type stackFixture struct {
	t   *testing.T
	ctx context.Context
	st  store.Store
	srv *Server
}

func newStackFixture(t *testing.T, st store.Store) *stackFixture {
	srv := NewServer(st)
	t.Cleanup(srv.Close)
	return &stackFixture{t: t, ctx: context.Background(), st: st, srv: srv}
}

func (f *stackFixture) begin(parent string) string {
	f.t.Helper()
	r, _ := f.srv.BeginTx(f.ctx, &storev1.BeginTxRequest{ParentTxId: parent})
	if r.GetError() != nil {
		f.t.Fatalf("BeginTx(%q): %v", parent, r.GetError())
	}
	return r.TxId
}

func (f *stackFixture) create(tx, id string) *storev1.Error {
	r, _ := f.srv.TenantsCreate(f.ctx, &storev1.TenantWrite{TxId: tx, Value: tenantPB(id)})
	return r.GetError()
}

func (f *stackFixture) mustCreate(tx, id string) {
	f.t.Helper()
	if e := f.create(tx, id); e != nil {
		f.t.Fatalf("create %s: %v", id, e)
	}
}

func (f *stackFixture) end(commit bool, tx string) {
	f.t.Helper()
	var r *storev1.Result
	if commit {
		r, _ = f.srv.Commit(f.ctx, &storev1.EndTxRequest{TxId: tx})
	} else {
		r, _ = f.srv.Rollback(f.ctx, &storev1.EndTxRequest{TxId: tx})
	}
	if r.GetError() != nil {
		f.t.Fatalf("end(commit=%v) %s: %v", commit, tx, r.GetError())
	}
}

func (f *stackFixture) exists(id string) bool {
	_, err := f.st.Tenants().Get(f.ctx, id)
	return err == nil
}

// Rolling back a parent rolls back its open nested transactions first, and
// the whole tree's writes are undone.
func TestServerRollbackParentRollsBackChildren(t *testing.T) {
	eachStore(t, func(t *testing.T, st store.Store) {
		f := newStackFixture(t, st)
		p := f.begin("")
		c := f.begin(p)
		g := f.begin(c)
		f.mustCreate(g, "grandchild")
		f.end(false, p)
		for _, id := range []string{p, c, g} {
			if r, _ := f.srv.Commit(f.ctx, &storev1.EndTxRequest{TxId: id}); r.GetError() == nil {
				t.Fatalf("tx %s still open after its root was rolled back", id)
			}
		}
		if f.exists("grandchild") {
			t.Fatal("grandchild write persisted")
		}
		if n := openTxs(f.srv); n != 0 {
			t.Fatalf("%d transactions still registered", n)
		}
	})
}

// A tree is a stack: a parent with an open nested transaction refuses a
// second one, and accepts one again once the first has ended.
func TestServerSecondOpenChildRefused(t *testing.T) {
	eachStore(t, func(t *testing.T, st store.Store) {
		f := newStackFixture(t, st)
		p := f.begin("")
		a := f.begin(p)
		r, _ := f.srv.BeginTx(f.ctx, &storev1.BeginTxRequest{ParentTxId: p})
		if !isErr(r.GetError(), errOpenChild) {
			t.Fatalf("second child: %v, want the open-child error", r.GetError())
		}
		f.mustCreate(a, "a")
		f.end(true, a)
		b := f.begin(p)
		f.mustCreate(b, "b")
		f.end(false, b)
		f.end(true, p)
		if !f.exists("a") || f.exists("b") {
			t.Fatalf("a=%v b=%v, want a committed and b rolled back", f.exists("a"), f.exists("b"))
		}
	})
}

// Only the innermost transaction accepts calls and Commit; the parent works
// again once its child has ended.
func TestServerCallOnParentWithOpenChildRefused(t *testing.T) {
	eachStore(t, func(t *testing.T, st store.Store) {
		f := newStackFixture(t, st)
		p := f.begin("")
		f.mustCreate(p, "p1")
		c := f.begin(p)
		if e := f.create(p, "p2"); !isErr(e, errOpenChild) {
			t.Fatalf("call on the parent: %v, want the open-child error", e)
		}
		if r, _ := f.srv.TenantsGet(f.ctx, &storev1.TenantsGetRequest{TxId: p, Key: "p1"}); !isErr(r.GetError(), errOpenChild) {
			t.Fatalf("read on the parent: %v, want the open-child error", r.GetError())
		}
		if r, _ := f.srv.Commit(f.ctx, &storev1.EndTxRequest{TxId: p}); !isErr(r.GetError(), errOpenChild) {
			t.Fatalf("Commit of the parent: %v, want the open-child error", r.GetError())
		}
		f.mustCreate(c, "c")
		f.end(true, c)
		f.mustCreate(p, "p2")
		f.end(true, p)
		for _, id := range []string{"p1", "c", "p2"} {
			if !f.exists(id) {
				t.Fatalf("%s missing", id)
			}
		}
	})
}

// Rolling back the middle of a chain rolls back its descendants innermost
// first and leaves the root usable.
func TestServerRollbackMiddleUndoesChain(t *testing.T) {
	eachStore(t, func(t *testing.T, st store.Store) {
		f := newStackFixture(t, st)
		p := f.begin("")
		f.mustCreate(p, "p")
		m := f.begin(p)
		f.mustCreate(m, "m")
		i := f.begin(m)
		f.mustCreate(i, "i")
		j := f.begin(i)
		f.mustCreate(j, "j")
		f.end(false, m)
		for _, id := range []string{m, i, j} {
			if e := f.create(id, "x"); !isErr(e, errUnknownTx) {
				t.Fatalf("call on rolled-back %s: %v, want unknown", id, e)
			}
		}
		f.mustCreate(p, "p2")
		n := f.begin(p) // the root takes a new nested transaction
		f.mustCreate(n, "n")
		f.end(true, n)
		f.end(true, p)
		for id, want := range map[string]bool{"p": true, "p2": true, "n": true, "m": false, "i": false, "j": false} {
			if f.exists(id) != want {
				t.Errorf("%s exists = %v, want %v", id, !want, want)
			}
		}
	})
}

// Calls in a nested transaction count as activity for its ancestors, so a
// parent is not rolled back by its idle timer while its child is in use.
func TestServerChildActivityKeepsParentAlive(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New(), WithTxIdleTimeout(150*time.Millisecond))
	defer srv.Close()
	p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	c, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
	for i := range 8 { // 8 × 50ms > idle timeout
		time.Sleep(50 * time.Millisecond)
		r, _ := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: c.TxId, Value: tenantPB(fmt.Sprint("t", i))})
		if r.GetError() != nil {
			t.Fatalf("call %d in the child: %v", i, r.GetError())
		}
	}
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: c.TxId}); r.GetError() != nil {
		t.Fatal(r.GetError())
	}
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() != nil {
		t.Fatal(r.GetError())
	}
}

// A nested BeginTx that loses the race with its parent's end must fail and
// must not start a nested transaction on the finished parent. The test holds
// the tree lock so that both calls are waiting on it before either proceeds.
func TestServerNestedBeginRacesParentEnd(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint("commit=", commit), func(t *testing.T) {
			ctx := context.Background()
			mem := memory.New()
			srv := NewServer(mem)
			defer srv.Close()
			p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
			srv.mu.Lock()
			h := srv.txs[p.TxId]
			srv.mu.Unlock()

			h.tree.lock.Lock()
			child := make(chan *storev1.BeginTxResponse, 1)
			go func() {
				r, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
				child <- r
			}()
			time.Sleep(20 * time.Millisecond) // let the nested BeginTx block on the tree lock
			end := make(chan *storev1.Result, 1)
			go func() {
				if commit {
					r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: p.TxId})
					end <- r
				} else {
					r, _ := srv.Rollback(ctx, &storev1.EndTxRequest{TxId: p.TxId})
					end <- r
				}
			}()
			for openTxs(srv) != 0 { // the end has unregistered the parent
				time.Sleep(time.Millisecond)
			}
			h.tree.lock.Unlock()

			if r := <-end; r.GetError() != nil {
				t.Fatalf("end: %v", r.GetError())
			}
			if r := <-child; r.GetError() == nil {
				t.Fatalf("nested BeginTx on an ending parent succeeded (tx %s)", r.TxId)
			}
			if n := openTxs(srv); n != 0 {
				t.Fatalf("%d transactions still registered", n)
			}
		})
	}
}

// A BeginTx whose caller gives up while it waits for the store's
// transaction lock must not leave a transaction behind holding that lock.
func TestServerBeginTxCancelledWhileWaiting(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	defer srv.Close()
	first, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})

	cctx, cancel := context.WithCancel(ctx)
	got := make(chan *storev1.BeginTxResponse, 1)
	go func() {
		r, _ := srv.BeginTx(cctx, &storev1.BeginTxRequest{})
		got <- r
	}()
	time.Sleep(20 * time.Millisecond) // blocked on memory's txMu
	cancel()
	if r := <-got; r.GetError() == nil {
		t.Fatal("cancelled BeginTx returned a transaction")
	}
	srv.Commit(ctx, &storev1.EndTxRequest{TxId: first.TxId})

	done := make(chan error, 1)
	go func() { done <- mem.WithTx(ctx, func(store.Store) error { return nil }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled BeginTx left the store locked")
	}
	if n := openTxs(srv); n != 0 {
		t.Fatalf("%d transactions still registered", n)
	}
}

// A BeginTx whose context is already done never leaves a transaction
// registered, root or nested, whichever branch finishes the race.
func TestServerBeginTxAlreadyCancelled(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	defer srv.Close()
	parent, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	for i := 0; i < 50; i++ {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		for _, p := range []string{"", parent.TxId} {
			r, err := srv.BeginTx(cctx, &storev1.BeginTxRequest{ParentTxId: p})
			if err != nil || r.GetError() == nil {
				t.Fatalf("cancelled BeginTx(parent %q) = %v, %v; want an error", p, r, err)
			}
		}
	}
	if n := openTxs(srv); n != 1 {
		t.Fatalf("%d transactions registered, want only the parent", n)
	}
	if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: parent.TxId}); r.GetError() != nil {
		t.Fatalf("commit parent: %v", r.GetError())
	}
	if err := mem.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Close rolls back open transactions, releases the store, and refuses new
// transactions.
func TestServerCloseRollsBackOpenTxs(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	c, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
	srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: c.TxId, Value: tenantPB("open")})
	srv.Close()
	if _, err := mem.Tenants().Get(ctx, "open"); err == nil {
		t.Fatal("write of an open transaction persisted after Close")
	}
	if err := mem.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if r, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{}); r.GetError() == nil {
		t.Fatal("BeginTx after Close succeeded")
	}
}

// TestServerTxStress drives many transaction trees at once. Run with -race.
func TestServerTxStress(t *testing.T) {
	eachStore(t, func(t *testing.T, st store.Store) {
		ctx := context.Background()
		srv := NewServer(st)
		const workers, rounds = 8, 50
		var (
			wg        sync.WaitGroup
			mu        sync.Mutex
			committed int
			errs      = make(chan error, workers)
		)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := func() error {
					for i := range rounds {
						outer, err := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
						if err != nil || outer.Error != nil {
							return fmt.Errorf("begin outer: %v %v", err, outer.GetError())
						}
						if r, _ := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: outer.TxId, Value: tenantPB(fmt.Sprintf("o-%d-%d", w, i))}); r.Error != nil {
							return fmt.Errorf("create outer: %v", r.Error)
						}
						inner, err := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: outer.TxId})
						if err != nil || inner.Error != nil {
							return fmt.Errorf("begin inner: %v %v", err, inner.GetError())
						}
						if r, _ := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: inner.TxId, Value: tenantPB(fmt.Sprintf("i-%d-%d", w, i))}); r.Error != nil {
							return fmt.Errorf("create inner: %v", r.Error)
						}
						n := 1
						if rand.IntN(2) == 0 {
							if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: inner.TxId}); r.Error != nil {
								return fmt.Errorf("commit inner: %v", r.Error)
							}
							n = 2
						} else if r, _ := srv.Rollback(ctx, &storev1.EndTxRequest{TxId: inner.TxId}); r.Error != nil {
							return fmt.Errorf("rollback inner: %v", r.Error)
						}
						if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: outer.TxId}); r.Error != nil {
							return fmt.Errorf("commit outer: %v", r.Error)
						}
						mu.Lock()
						committed += n
						mu.Unlock()
					}
					return nil
				}()
				if err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		ts, err := st.Tenants().List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(ts) != committed {
			t.Fatalf("stored %d tenants, committed %d creates", len(ts), committed)
		}
		closed := make(chan struct{})
		go func() { srv.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not return")
		}
	})
}

// TestServerTxChaos races every registry path against the others: calls,
// nested begins, commits and rollbacks at every level, on transactions that
// other goroutines may be ending, with an idle timeout short enough to fire
// mid-run. The only acceptable failures are the registry's own (unknown
// transaction, open child, closed) and a root BeginTx giving up on its
// deadline; any other error comes from the driver and means the registry
// misused a transaction. Nothing may deadlock, leak a registration or a
// goroutine (Close returns), or leave the store's transaction lock held.
// Run with -race.
func TestServerTxChaos(t *testing.T) {
	allowed := []error{errUnknownTx, errOpenChild, errClosed, context.DeadlineExceeded, context.Canceled}
	eachStore(t, func(t *testing.T, st store.Store) {
		ctx := context.Background()
		srv := NewServer(st, WithTxIdleTimeout(3*time.Millisecond))
		var (
			mu     sync.Mutex
			ids    []string
			ops    int
			bad    = map[string]int{}
			byKind = map[string]int{}
		)
		check := func(op string, e *storev1.Error) {
			mu.Lock()
			defer mu.Unlock()
			ops++
			if e == nil {
				byKind["ok"]++
				return
			}
			for _, a := range allowed {
				if isErr(e, a) {
					byKind[a.Error()]++
					return
				}
			}
			bad[op+": "+e.String()]++
		}
		pick := func() string {
			mu.Lock()
			defer mu.Unlock()
			if len(ids) == 0 || rand.IntN(4) == 0 {
				return ""
			}
			// Mostly recent transactions, which are likely still open.
			return ids[max(0, len(ids)-1-rand.IntN(6))]
		}
		var wg sync.WaitGroup
		for w := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range 300 {
					id := pick()
					switch rand.IntN(5) {
					case 0, 1:
						cctx, cancel := context.WithTimeout(ctx, 2*time.Millisecond)
						r, _ := srv.BeginTx(cctx, &storev1.BeginTxRequest{ParentTxId: id})
						cancel()
						check("begin", r.GetError())
						if r.GetError() == nil {
							mu.Lock()
							ids = append(ids, r.TxId)
							mu.Unlock()
						}
					case 2:
						r, _ := srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: id, Value: tenantPB(fmt.Sprintf("c-%d-%d", w, i))})
						check("create", r.GetError())
					case 3:
						r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: id})
						if id != "" {
							check("commit", r.GetError())
						}
					case 4:
						r, _ := srv.Rollback(ctx, &storev1.EndTxRequest{TxId: id})
						if id != "" {
							check("rollback", r.GetError())
						}
					}
				}
			}()
		}
		wg.Wait()
		closed := make(chan struct{})
		go func() { srv.Close(); close(closed) }()
		select {
		case <-closed:
		case <-time.After(10 * time.Second):
			t.Fatal("Close did not return")
		}
		t.Logf("%d checked operations: %v", ops, byKind)
		for e, n := range bad {
			t.Errorf("%d× driver-level error: %s", n, e)
		}
		if byKind["ok"] == 0 {
			t.Error("no operation succeeded; the test exercised nothing")
		}
		if n := openTxs(srv); n != 0 {
			t.Fatalf("%d transactions still registered after Close", n)
		}
		done := make(chan error, 1)
		go func() { done <- st.WithTx(ctx, func(store.Store) error { return nil }) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the store's transaction lock is still held")
		}
	})
}

// The embedded UnimplementedStoreServiceServer would hide a missing method,
// so call every RPC in the service descriptor and require that none answers
// Unimplemented. A panic (e.g. a store given a nil value) still proves the
// method is ours.
func TestServerImplementsEveryMethod(t *testing.T) {
	srv := NewServer(memory.New())
	defer srv.Close()
	v := reflect.ValueOf(srv)
	for _, md := range storev1.StoreService_ServiceDesc.Methods {
		m := v.MethodByName(md.MethodName)
		if !m.IsValid() {
			t.Errorf("%s: no such method", md.MethodName)
			continue
		}
		req := reflect.New(m.Type().In(1).Elem())
		var err error
		func() {
			defer func() { _ = recover() }()
			out := m.Call([]reflect.Value{reflect.ValueOf(context.Background()), req})
			err, _ = out[1].Interface().(error)
		}()
		if status.Code(err) == codes.Unimplemented {
			t.Errorf("%s is not implemented by *Server", md.MethodName)
		}
	}
}

// Values and errors travel together: Consume of a used code returns the
// code and ALREADY_USED; lists and counts are encoded.
func TestServerRepositoryRoundTrips(t *testing.T) {
	ctx := context.Background()
	srv := NewServer(memory.New())
	defer srv.Close()
	at := time.Date(2026, 5, 6, 7, 8, 9, 10, time.UTC)

	code, _ := authCodeToPB(&store.AuthCode{TenantID: "t", CodeHash: "h", ExpiresAt: at.Add(time.Hour), CreatedAt: at})
	if r, _ := srv.AuthCodesCreate(ctx, &storev1.AuthCodeWrite{Value: code}); r.Error != nil {
		t.Fatal(r.Error)
	}
	first, _ := srv.AuthCodesConsume(ctx, &storev1.ConsumeRequest{TenantId: "t", Hash: "h", At: tsToPB(at)})
	if first.Error != nil || first.Value == nil || !tsFromPB(first.Value.UsedAt).Equal(at) {
		t.Fatalf("first consume = %v", first)
	}
	replay, _ := srv.AuthCodesConsume(ctx, &storev1.ConsumeRequest{TenantId: "t", Hash: "h", At: tsToPB(at.Add(time.Second))})
	if replay.GetError().GetKind() != storev1.Error_KIND_ALREADY_USED || replay.Value == nil || replay.Value.ReplayedAt == nil {
		t.Fatalf("replay = %v, want ALREADY_USED with the code", replay)
	}

	ticket, _ := passwordResetTicketToPB(&store.PasswordResetTicket{TenantID: "t", ID: "p1", TokenHash: "th", ExpiresAt: at.Add(time.Hour), CreatedAt: at})
	if r, _ := srv.PasswordResetTicketsCreate(ctx, &storev1.PasswordResetTicketWrite{Value: ticket}); r.Error != nil {
		t.Fatal(r.Error)
	}
	used, _ := srv.PasswordResetTicketsConsume(ctx, &storev1.ConsumeRequest{TenantId: "t", Hash: "th", At: tsToPB(at)})
	if used.Error != nil || used.Value == nil || !tsFromPB(used.Value.UsedAt).Equal(at) {
		t.Fatalf("first ticket consume = %v", used)
	}
	again, _ := srv.PasswordResetTicketsConsume(ctx, &storev1.ConsumeRequest{TenantId: "t", Hash: "th", At: tsToPB(at.Add(time.Second))})
	if again.GetError().GetKind() != storev1.Error_KIND_ALREADY_USED || again.Value == nil || !tsFromPB(again.Value.UsedAt).Equal(at) {
		t.Fatalf("ticket replay = %v, want ALREADY_USED with the ticket and its first UsedAt", again)
	}

	for _, id := range []string{"b", "a"} {
		srv.TenantsCreate(ctx, &storev1.TenantWrite{Value: tenantPB(id)})
	}
	list, _ := srv.TenantsList(ctx, &storev1.TenantsListRequest{})
	if list.Error != nil || len(list.Values) != 2 || list.Values[0].Id != "a" {
		t.Fatalf("list = %v", list)
	}

	n, _ := srv.AuthCodesDeleteExpired(ctx, &storev1.DeleteExpiredRequest{Before: tsToPB(at.Add(2 * time.Hour))})
	if n.Error != nil || n.Count != 1 {
		t.Fatalf("delete expired = %v, want 1", n)
	}
}

func openTxs(s *Server) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.txs)
}
