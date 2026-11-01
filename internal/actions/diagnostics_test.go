package actions

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
)

func TestActionConsoleDiagnosticBounds(t *testing.T) {
	for _, kind := range []string{"count", "bytes", "expiry"} {
		t.Run(kind, func(t *testing.T) {
			p := &procState{}
			ctx := logscrub.WithCredentials(context.Background(), "request-password")
			p.add(ctx)
			if line, ok := p.scrub("late request-password"); !ok || strings.Contains(line, "request-password") {
				t.Fatalf("unsafe delayed output: %q %v", line, ok)
			}
			switch kind {
			case "count":
				for i := 0; i < 257; i++ {
					p.add(logscrub.WithCredentials(context.Background(), fmt.Sprintf("credential-%d", i)))
				}
			case "bytes":
				p.add(logscrub.WithCredentials(context.Background(), strings.Repeat("s", 64*1024)))
			case "expiry":
				p.until = time.Now().Add(-time.Second)
			}
			if _, ok := p.scrub("late request-password"); ok {
				t.Fatal("diagnostics not muted")
			}
			p.add(ctx)
			if len(p.values) != 0 || p.bytes != 0 {
				t.Fatal("retains exhausted credential history")
			}
			if _, ok := p.scrub("late request-password"); ok {
				t.Fatal("mute was not permanent")
			}
		})
	}
}

func TestActionConsoleExpiredCapturePermanentlyClearsState(t *testing.T) {
	p := &procState{}
	p.add(logscrub.WithCredentials(context.Background(), "prior-secret"))
	p.until = time.Now().Add(-time.Second)
	red := customdb.NewRedactor(nil)
	for range 2 {
		if got := p.capture(context.Background(), red, []string{"prior-secret"}); len(got) != 0 {
			t.Fatalf("expired capture: %q", got)
		}
		p.add(logscrub.WithCredentials(context.Background(), "new-secret"))
	}
	if !p.muted || p.bytes != 0 || len(p.values) != 0 {
		t.Fatal("expired history retained")
	}
	// Retirement gives a new process an independent diagnostic lifetime.
	fresh := &procState{}
	fresh.add(context.Background())
	if got := fresh.capture(context.Background(), red, []string{"new process"}); len(got) != 1 || got[0] != "new process" {
		t.Fatalf("fresh process muted: %q", got)
	}
}
