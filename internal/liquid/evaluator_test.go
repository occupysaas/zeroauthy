package liquid

import (
	"context"
	"errors"
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
