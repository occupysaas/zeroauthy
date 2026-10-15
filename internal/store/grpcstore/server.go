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

// heldTx is one open transaction. A nested transaction runs on its parent's
// underlying transaction (a SQL savepoint, a memory snapshot), so every
// transaction in one tree shares the root's lock: no two calls, and no
// BeginTx/finish, touch the same underlying transaction at once.
type heldTx struct {
	id     string
	parent *heldTx
	lock   *sync.Mutex // the root's; shared by the whole tree
	st     store.Store
	kids   map[string]*heldTx // nested transactions not yet ended (guarded by Server.mu)
	end    chan error         // nil = commit, errRollback = rollback
	result chan error         // the store's WithTx result
	done   chan struct{}      // closed once WithTx has returned and h left its parent's kids
	timer  *time.Timer        // the idle timer; stopped and reset only under lock
	cancel context.CancelFunc
}

func newTxID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// BeginTx opens a transaction, nested in ParentTxId when it is set.
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
	}
	s.wg.Add(1) // under mu while open, so Close's Wait never races an Add
	s.mu.Unlock()
	started := false
	defer func() {
		if !started {
			s.wg.Done()
		}
	}()

	base, lock := s.st, &sync.Mutex{}
	if parent != nil {
		base, lock = parent.st, parent.lock
	}
	lock.Lock() // the nested WithTx issues its savepoint on the shared transaction
	defer lock.Unlock()
	if parent != nil {
		// Beginning a nested transaction is activity on its ancestors. A
		// stopped timer means an ancestor is ending.
		if !stopTimers(parent) {
			return fail(errUnknownTx)
		}
		defer s.resetTimers(parent)
	}

	txCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	h := &heldTx{id: newTxID(), parent: parent, lock: lock, kids: map[string]*heldTx{},
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
	err := errClosed
	if !s.closed {
		err = nil
		if parent != nil && s.txs[parent.id] != parent {
			err = errUnknownTx // the parent ended while this one began
		}
	}
	if err != nil {
		s.mu.Unlock()
		h.end <- errRollback // still under the tree lock: the parent waits for it
		<-h.result
		cancel()
		return fail(err)
	}
	h.timer = time.AfterFunc(s.idle, func() { _ = s.finish(h.id, errRollback) })
	s.txs[h.id] = h
	if parent != nil {
		parent.kids[h.id] = h
	}
	s.mu.Unlock()
	return &storev1.BeginTxResponse{TxId: h.id}, nil
}

// finish ends transaction id with signal (nil commits, errRollback rolls
// back) and returns the store's result; a rollback is not an error. Commit
// refuses while nested transactions are open; Rollback first rolls back the
// open nested transactions, innermost first.
//
// A transaction leaves Server.txs before its WithTx ends (no new calls
// reach it) but leaves its parent's kids only after (the parent cannot end
// while the nested WithTx still runs on its transaction).
func (s *Server) finish(id string, signal error) error {
	s.mu.Lock()
	h := s.txs[id]
	if h == nil {
		s.mu.Unlock()
		return errUnknownTx
	}
	for len(h.kids) > 0 {
		if signal == nil {
			s.mu.Unlock()
			return errOpenChild
		}
		kids := make([]*heldTx, 0, len(h.kids))
		for _, k := range h.kids {
			kids = append(kids, k)
		}
		s.mu.Unlock()
		for _, k := range kids {
			_ = s.finish(k.id, errRollback) // unknown if already ending
			<-k.done
		}
		s.mu.Lock()
		if s.txs[id] != h { // finished concurrently (e.g. the idle timer)
			s.mu.Unlock()
			return errUnknownTx
		}
	}
	delete(s.txs, id)
	s.mu.Unlock()

	h.lock.Lock() // wait for an in-flight call in this tree
	h.timer.Stop()
	h.end <- signal
	err := <-h.result
	h.lock.Unlock()
	h.cancel()

	if h.parent != nil {
		s.mu.Lock()
		delete(h.parent.kids, id)
		s.mu.Unlock()
	}
	close(h.done)
	if errors.Is(err, errRollback) {
		return nil
	}
	return err
}

// Commit commits a transaction; a nested one releases its savepoint.
func (s *Server) Commit(_ context.Context, r *storev1.EndTxRequest) (*storev1.Result, error) {
	return &storev1.Result{Error: errToPB(s.finish(r.TxId, nil))}, nil
}

// Rollback rolls a transaction back with its nested transactions.
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
// the held transaction txID. Calls in one transaction tree are serialized,
// and each call restarts the idle timers of the transaction and its
// ancestors.
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
	h.lock.Lock()
	defer h.lock.Unlock()
	if !stopTimers(h) { // a timer already fired or finish stopped it: it is ending
		return errUnknownTx
	}
	defer s.resetTimers(h)
	return f(h.st)
}

// stopTimers stops the idle timers of h and its ancestors so that none
// fires during a call. It reports false if one was not running, which
// means that transaction is ending (its timer fired, or finish stopped it).
// The caller holds the tree lock.
func stopTimers(h *heldTx) bool {
	for n := h; n != nil; n = n.parent {
		if !n.timer.Stop() {
			return false
		}
	}
	return true
}

// resetTimers restarts the timers stopTimers stopped. The caller holds the
// tree lock; a transaction that started ending meanwhile stops its own
// timer again once it holds the tree lock.
func (s *Server) resetTimers(h *heldTx) {
	for n := h; n != nil; n = n.parent {
		n.timer.Reset(s.idle)
	}
}
