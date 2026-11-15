package liquid

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// This parser-internal case moved with the evaluator from email/render_test.go.
// Email's public renderer regression cases remain in the email package.
func TestRenderEvaluationSteps(t *testing.T) {
	state := renderState{ctx: context.Background(), deadline: time.Now().Add(time.Second)}
	for i := 0; i < maxSteps; i++ {
		if err := state.step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if err := state.step(); !errors.Is(err, ErrRenderLimit) {
		t.Fatalf("step %d error = %v, want ErrRenderLimit", maxSteps+1, err)
	}
}

// Cancelling the caller's context stops a render already under way. Parsing
// with a live context and cancelling before evaluation makes the order
// deterministic on any CPU count, unlike racing a timer against the render.
func TestRenderStopsWhenCancelledMidway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := renderState{ctx: ctx, deadline: time.Now().Add(time.Second), vars: map[string]any{}}
	nodes, _, err := state.parse("{% for x in (1..10000) %}{{ x }}{% endfor %}", 0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	var out strings.Builder
	if err := state.renderNodes(&out, nodes); !errors.Is(err, context.Canceled) {
		t.Fatalf("renderNodes() error = %v, want context.Canceled", err)
	}
}

// The shared capacity refuses work once maxConcurrent renders hold it, on
// every entry point, and a refused call gives back the slot it took. Holding
// the slots directly keeps this independent of CPU count; the email package's
// concurrent test can only observe it when real renders overlap.
func TestRenderCapacity(t *testing.T) {
	if n := activeRenders.Load(); n != 0 {
		t.Fatalf("%d render slots in use before the test", n)
	}
	activeRenders.Add(maxConcurrent)
	held := int32(maxConcurrent)
	defer func() { activeRenders.Add(-held) }()

	ctx := context.Background()
	r, _ := NewRenderer()
	if _, err := r.Render(ctx, RenderInput{Fields: map[string]string{"body": "x"}}); !errors.Is(err, ErrRenderCapacity) {
		t.Errorf("email Render() error = %v, want ErrRenderCapacity", err)
	}
	if _, err := RenderLiquid(ctx, "x", nil, 0); !errors.Is(err, ErrRenderCapacity) {
		t.Errorf("RenderLiquid() error = %v, want ErrRenderCapacity", err)
	}
	if _, err := Render(ctx, "x", nil, nil, Limits{}); !errors.Is(err, ErrRenderCapacity) {
		t.Errorf("Render() error = %v, want ErrRenderCapacity", err)
	}
	if err := Validate(ctx, "x", Limits{}); !errors.Is(err, ErrRenderCapacity) {
		t.Errorf("Validate() error = %v, want ErrRenderCapacity", err)
	}
	if n := SlotsInUse(); n != maxConcurrent {
		t.Fatalf("SlotsInUse() = %d after refusals, want %d", n, maxConcurrent)
	}

	activeRenders.Add(-1)
	held--
	if out, err := RenderLiquid(ctx, "x", nil, 0); err != nil || out != "x" {
		t.Fatalf("RenderLiquid() with a free slot = (%q, %v)", out, err)
	}
	if n := SlotsInUse(); n != maxConcurrent-1 {
		t.Fatalf("SlotsInUse() = %d after a render, want %d", n, maxConcurrent-1)
	}
}
