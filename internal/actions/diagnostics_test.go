package actions

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

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
