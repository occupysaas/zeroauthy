package mgmt

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

const sseCycle = 5 * time.Minute

// All deadline changes are serialized so a send cannot undo cancellation's
// immediate expiry. No lock is held across Write or Flush.
type sseTransport struct {
	controller   *http.ResponseController
	mu           sync.Mutex
	interrupted  bool
	started      time.Time
	realDeadline time.Time
	now          func() time.Time
}

func (t *sseTransport) prepare() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.interrupted {
		return context.Canceled
	}
	now := time.Now()
	deadline := t.realDeadline
	// ResponseController uses the real clock; Now can be a logical test clock.
	// Never extend the original real lifetime when translating remaining time.
	if logical := now.Add(sseCycle - t.now().Sub(t.started)); logical.Before(deadline) {
		deadline = logical
	}
	if !deadline.After(now) {
		t.interrupted = true
		_ = t.controller.SetWriteDeadline(now)
		return context.DeadlineExceeded
	}
	err := t.controller.SetWriteDeadline(deadline)
	// In-process recorders may lack deadlines; net/http transports support them.
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}
func (t *sseTransport) interrupt() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.interrupted = true
	_ = t.controller.SetWriteDeadline(time.Now())
}

// One watcher owns the polling timer and lifetime signals, including while the
// serving goroutine is blocked in transport I/O. cleanup joins it before the
// ResponseWriter can be reused by net/http. Poll notifications may coalesce;
// cycle/cancellation notifications cannot be lost behind a blocked send.
func (h *Handlers) sseLifetime(parent context.Context, transport *sseTransport) (context.Context, <-chan struct{}, func()) {
	ctx, cancel := context.WithCancel(parent)
	var ticks <-chan time.Time
	var stopTicks func()
	if h.sseTicks != nil {
		ticks, stopTicks = h.sseTicks()
	} else {
		ticker := time.NewTicker(time.Second)
		ticks, stopTicks = ticker.C, ticker.Stop
	}
	timer := time.NewTimer(time.Until(transport.realDeadline))
	polls := make(chan struct{}, 1)
	stop, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				transport.interrupt()
				return
			case <-timer.C:
				transport.interrupt()
				cancel()
				return
			case _, ok := <-ticks:
				if !ok || h.now().Sub(transport.started) >= sseCycle {
					transport.interrupt()
					cancel()
					return
				}
				select {
				case polls <- struct{}{}:
				default:
				}
			}
		}
	}()
	cleanup := func() { close(stop); cancel(); <-exited; timer.Stop(); stopTicks() }
	return ctx, polls, cleanup
}
