package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestConnectionKeys(t *testing.T) {
	storetest.RunSuites(t, func(t *testing.T) store.Store { return inProcess(t) }, "ConnectionKeys")
}

func TestConnectionKeysCapabilityLatch(t *testing.T) {
	for _, missing := range []bool{false, true} {
		faults := &eventsFaults{ckMissing: missing}
		c := serveEventsFaults(t, memory.New(), faults)
		for range 3 {
			_, e := c.ConnectionKeys().List(context.Background(), "t", "c")
			if errors.Is(e, store.ErrConnectionKeysUnavailable) != missing {
				t.Fatal(e)
			}
		}
		if faults.ckProbes.Load() != 1 {
			t.Fatalf("probed %d times", faults.ckProbes.Load())
		}
		if c.ConnectionKeysSupported() == missing {
			t.Fatal("wrong capability")
		}
	}
}
