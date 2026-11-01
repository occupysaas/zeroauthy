package logscrub_test

import (
	"context"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

type detachedContextProbe struct {
	context.Context
	finished  bool
	lateReads int
}

func (p *detachedContextProbe) Value(key any) any {
	if p.finished {
		p.lateReads++
	}
	return p.Context.Value(key)
}

func TestDetachedScrubber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := &detachedContextProbe{Context: logscrub.WithValues(ctx, "acme")}
	scrub := logscrub.DetachedScrubber(probe)
	// Later derivation and cancellation cannot change a captured mask.
	_ = logscrub.WithValues(probe, "later-value")
	probe.finished = true
	cancel()
	value := map[string]any{"password": "hidden", "acme": "acme", "encoded": `{"note":"a\u0063me"}`, "later": "later-value"}
	out := scrub(value).(map[string]any)
	if probe.lateReads != 0 {
		t.Fatalf("detached scrubber read request context %d times", probe.lateReads)
	}
	if out["password"] != logscrub.Marker || out[logscrub.Marker] != logscrub.Marker || out["later"] != "later-value" || strings.Contains(out["encoded"].(string), "acme") {
		t.Fatalf("detached masks %+v", out)
	}
	if value["password"] != "hidden" || value["acme"] != "acme" {
		t.Fatal("detached scrubber mutated input")
	}
}
