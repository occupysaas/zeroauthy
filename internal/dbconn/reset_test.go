package dbconn

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A panic in a background send is recovered and logged without its value,
// which could hold the message; it must not crash the process.
func TestGoRunRecoversPanic(t *testing.T) {
	var out syncBuffer
	h := &Handlers{Log: slog.New(slog.NewTextHandler(&out, nil))} // Go is nil: the go statement
	h.goRun(func() { panic("send https://x.test/u/reset-password?ticket=SECRET") })
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), "level=ERROR") {
		if time.Now().After(deadline) {
			t.Fatal("panic was not logged")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatalf("log contains the panic value: %s", out.String())
	}
}
