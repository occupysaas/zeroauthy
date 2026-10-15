package grpcstore

import (
	"context"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
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

// Rolling back a parent rolls back its open nested transactions first, and
// the whole tree's writes are undone.
func TestServerRollbackParentRollsBackChildren(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
	defer srv.Close()
	p, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{})
	c, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: p.TxId})
	g, _ := srv.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: c.TxId})
	srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: g.TxId, Value: tenantPB("grandchild")})
	if r, _ := srv.Rollback(ctx, &storev1.EndTxRequest{TxId: p.TxId}); r.GetError() != nil {
		t.Fatal(r.GetError())
	}
	for _, id := range []string{p.TxId, c.TxId, g.TxId} {
		if r, _ := srv.Commit(ctx, &storev1.EndTxRequest{TxId: id}); r.GetError() == nil {
			t.Fatalf("tx %s still open after its root was rolled back", id)
		}
	}
	if _, err := mem.Tenants().Get(ctx, "grandchild"); err == nil {
		t.Fatal("grandchild write persisted")
	}
	if n := openTxs(srv); n != 0 {
		t.Fatalf("%d transactions still registered", n)
	}
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

			h.lock.Lock()
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
			h.lock.Unlock()

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
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem)
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
	ts, err := mem.Tenants().List(ctx)
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
}

// TestServerTxChaos races every registry path against the others: calls,
// nested begins, commits and rollbacks at every level, on transactions that
// other goroutines may be ending, with an idle timeout short enough to fire
// mid-run. Nothing may deadlock, leak a registration or a goroutine (Close
// returns), or leave memory's transaction lock held. Run with -race.
func TestServerTxChaos(t *testing.T) {
	ctx := context.Background()
	mem := memory.New()
	srv := NewServer(mem, WithTxIdleTimeout(3*time.Millisecond))
	var (
		mu  sync.Mutex
		ids []string
	)
	pick := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 0 || rand.IntN(4) == 0 {
			return ""
		}
		return ids[rand.IntN(len(ids))]
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
					if r.GetError() == nil {
						mu.Lock()
						ids = append(ids, r.TxId)
						mu.Unlock()
					}
				case 2:
					srv.TenantsCreate(ctx, &storev1.TenantWrite{TxId: id, Value: tenantPB(fmt.Sprintf("c-%d-%d", w, i))})
				case 3:
					srv.Commit(ctx, &storev1.EndTxRequest{TxId: id})
				case 4:
					srv.Rollback(ctx, &storev1.EndTxRequest{TxId: id})
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
	if n := openTxs(srv); n != 0 {
		t.Fatalf("%d transactions still registered after Close", n)
	}
	if err := mem.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
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
