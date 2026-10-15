package grpcstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// errRollback ends a held transaction without committing it.
var errRollback = errors.New("grpcstore: rolled back")

var (
	errUnknownTx = errors.New("grpcstore: unknown or finished transaction")
	errOpenChild = errors.New("grpcstore: transaction has an open nested transaction")
	errClosed    = errors.New("grpcstore: server closed")
)

// Server exposes a store.Store as a StoreService. Transactions opened by
// BeginTx run the store's own WithTx in a goroutine that holds the
// transaction open until Commit, Rollback, the idle timeout or Close.
//
// Locking order: Server.mu is held only briefly and never while waiting for
// a tree lock or a store call. A tree lock may be held while taking
// Server.mu, never the other way round.
type Server struct {
	storev1.UnimplementedStoreServiceServer
	st   store.Store
	idle time.Duration

	mu     sync.Mutex
	txs    map[string]*heldTx // open transactions
	closed bool
	wg     sync.WaitGroup // transaction goroutines; Add only under mu while !closed
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithTxIdleTimeout sets how long a transaction may go without a call
// before the server rolls it back. The default is 60 seconds.
func WithTxIdleTimeout(d time.Duration) ServerOption { return func(s *Server) { s.idle = d } }

// NewServer returns a Server that serves st.
func NewServer(st store.Store, opts ...ServerOption) *Server {
	s := &Server{st: st, idle: 60 * time.Second, txs: map[string]*heldTx{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

// txTree is what all transactions of one tree share. A nested transaction
// runs on its parent's underlying transaction (a SQL savepoint, a memory
// snapshot), so the tree has one lock: no two calls, and no BeginTx/finish,
// touch the same underlying transaction at once. The tree also has one idle
// timer: any activity in the tree restarts it, and when it fires the root is
// rolled back with everything nested in it.
type txTree struct {
	lock  sync.Mutex
	timer *time.Timer // stopped and reset only under lock; set before the root is registered
}

// heldTx is one open transaction. A tree is a stack, like the savepoints it
// maps to: a transaction has at most one open nested transaction, and only
// the innermost one accepts repository calls and Commit.
type heldTx struct {
	id     string
	parent *heldTx
	tree   *txTree
	st     store.Store
	child  *heldTx       // the open nested transaction (guarded by Server.mu)
	end    chan error    // nil = commit, errRollback = rollback
	result chan error    // the store's WithTx result
	done   chan struct{} // closed once WithTx has returned and h left its parent
	cancel context.CancelFunc
}

func newTxID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// BeginTx opens a transaction, nested in ParentTxId when it is set. A parent
// that already has an open nested transaction is refused (errOpenChild).
//
// A root BeginTx stops waiting for the store when ctx is done. A nested one
// waits for the tree lock (an in-flight call in the tree) without honouring
// ctx; it is quick once it holds the lock.
func (s *Server) BeginTx(ctx context.Context, r *storev1.BeginTxRequest) (*storev1.BeginTxResponse, error) {
	fail := func(err error) (*storev1.BeginTxResponse, error) {
		return &storev1.BeginTxResponse{Error: errToPB(err)}, nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fail(errClosed)
	}
	var parent *heldTx
	if r.ParentTxId != "" {
		if parent = s.txs[r.ParentTxId]; parent == nil {
			s.mu.Unlock()
			return fail(errUnknownTx)
		}
		if parent.child != nil { // fast path; rechecked at registration
			s.mu.Unlock()
			return fail(errOpenChild)
		}
	}
	s.wg.Add(1) // under mu while open, so Close's Wait never races an Add
	s.mu.Unlock()
	started := false
	defer func() {
		if !started {
			s.wg.Done()
		}
	}()

	// A caller that gave up while the transaction was being registered must
	// not leave it behind. Rolling it back needs the tree lock, so it runs
	// after the deferred unlock below.
	var abandon string
	defer func() {
		if abandon != "" {
			_ = s.finish(abandon, errRollback)
		}
	}()

	base, tree := s.st, &txTree{}
	if parent != nil {
		base, tree = parent.st, parent.tree
	}
	tree.lock.Lock() // the nested WithTx issues its savepoint on the shared transaction
	defer tree.lock.Unlock()
	if parent != nil {
		// Beginning a nested transaction is activity in the tree. A timer
		// that is not running means the tree is being rolled back.
		if !tree.timer.Stop() {
			return fail(errUnknownTx)
		}
		defer tree.timer.Reset(s.idle)
	}

	txCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &heldTx{id: newTxID(), parent: parent, tree: tree,
		end: make(chan error, 1), result: make(chan error, 1), done: make(chan struct{}), cancel: cancel}
	ready := make(chan struct{})
	started = true
	go func() {
		defer s.wg.Done()
		h.result <- base.WithTx(txCtx, func(tx store.Store) error {
			h.st = tx
			close(ready)
			return <-h.end
		})
	}()

	// A root BeginTx may wait a long time for the store's transaction lock;
	// if its caller gives up, the transaction must not be left behind. A
	// nested one is quick and shares the tree's transaction, so it always
	// runs to completion while the tree lock is held.
	var gaveUp <-chan struct{}
	if parent == nil {
		gaveUp = ctx.Done()
	}
	select {
	case <-ready:
	case err := <-h.result: // WithTx failed before running fn
		cancel()
		return fail(err)
	case <-gaveUp:
		h.end <- errRollback // fn returns at once if it ever starts
		cancel()             // and a driver still beginning gives up
		return fail(ctx.Err())
	}

	s.mu.Lock()
	var err error
	switch {
	case s.closed:
		err = errClosed
	case parent != nil && s.txs[parent.id] != parent:
		err = errUnknownTx // the parent ended while this one began
	case parent != nil && parent.child != nil:
		err = errOpenChild // a sibling registered first
	}
	if err != nil {
		s.mu.Unlock()
		h.end <- errRollback // still under the tree lock: the parent waits for it
		<-h.result
		cancel()
		return fail(err)
	}
	if parent == nil {
		tree.timer = time.AfterFunc(s.idle, func() { _ = s.finish(h.id, errRollback) })
	} else {
		parent.child = h
	}
	s.txs[h.id] = h
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		abandon = h.id
		return fail(err)
	}
	return &storev1.BeginTxResponse{TxId: h.id}, nil
}

// finish ends transaction id with signal (nil commits, errRollback rolls
// back) and returns the store's result; a rollback is not an error. Commit
// refuses while a nested transaction is open; Rollback first rolls back the
// open nested chain, innermost first.
//
// A transaction leaves Server.txs before its WithTx ends (no new calls
// reach it) but leaves its parent only after (the parent cannot end while
// the nested WithTx still runs on its transaction).
func (s *Server) finish(id string, signal error) error {
	s.mu.Lock()
	h := s.txs[id]
	if h == nil {
		s.mu.Unlock()
		return errUnknownTx
	}
	for h.child != nil {
		if signal == nil {
			s.mu.Unlock()
			return errOpenChild
		}
		k := h.child
		s.mu.Unlock()
		_ = s.finish(k.id, errRollback) // rolls back k's own chain first; unknown if already ending
		<-k.done
		s.mu.Lock()
		if s.txs[id] != h { // finished concurrently (e.g. the idle timer)
			s.mu.Unlock()
			return errUnknownTx
		}
	}
	delete(s.txs, id)
	s.mu.Unlock()

	t := h.tree
	t.lock.Lock() // wait for an in-flight call in this tree
	if h.parent == nil {
		t.timer.Stop()
	} else if t.timer.Stop() { // ending a nested transaction is activity in the tree
		t.timer.Reset(s.idle)
	}
	h.end <- signal
	err := <-h.result
	if h.parent != nil {
		s.mu.Lock() // tree lock, then Server.mu: the permitted order
		h.parent.child = nil
		s.mu.Unlock()
	}
	t.lock.Unlock()
	h.cancel()
	close(h.done)
	if errors.Is(err, errRollback) {
		return nil
	}
	return err
}

// Commit commits a transaction; a nested one releases its savepoint. It
// waits for the tree lock (an in-flight call in the tree) without
// honouring ctx.
func (s *Server) Commit(_ context.Context, r *storev1.EndTxRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.finish(r.TxId, nil))}, nil
}

// Rollback rolls a transaction back with its open nested chain, innermost
// first. It waits for the tree lock without honouring ctx.
func (s *Server) Rollback(_ context.Context, r *storev1.EndTxRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.finish(r.TxId, errRollback))}, nil
}

// Ping checks the store.
func (s *Server) Ping(ctx context.Context, _ *storev1.PingRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.st.Ping(ctx))}, nil
}

// Close rolls back every open transaction (roots; their nested
// transactions go first), refuses new ones, and waits for the transaction
// goroutines. It does not close the store.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	var roots []string
	for id, h := range s.txs {
		if h.parent == nil {
			roots = append(roots, id)
		}
	}
	s.mu.Unlock()
	for _, id := range roots {
		_ = s.finish(id, errRollback)
	}
	s.wg.Wait()
}

// with runs f against the store a request addresses: the base store, or
// the held transaction txID. Only the innermost transaction of a tree
// accepts calls (errOpenChild otherwise). Calls in one tree are serialized,
// and each restarts the tree's idle timer.
func (s *Server) with(txID string, f func(store.Store) error) error {
	if txID == "" {
		return f(s.st)
	}
	s.mu.Lock()
	h := s.txs[txID]
	s.mu.Unlock()
	if h == nil {
		return errUnknownTx
	}
	t := h.tree
	t.lock.Lock()
	defer t.lock.Unlock()
	// Under the tree lock no nested transaction can begin or end, so this
	// answer holds for the whole call.
	s.mu.Lock()
	live, child := s.txs[txID] == h, h.child
	s.mu.Unlock()
	switch {
	case !live:
		return errUnknownTx
	case child != nil:
		return errOpenChild
	case !t.timer.Stop(): // the idle timer fired: the tree is being rolled back
		return errUnknownTx
	}
	defer t.timer.Reset(s.idle)
	return f(h.st)
}
