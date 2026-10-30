package grpcstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// Task 5 supplies the transport; these are deliberately real conformance
// wrappers, not skips that could hide an unavailable capability.
func TestLogs(t *testing.T) {
	for name, f := range map[string]func(*testing.T) *Client{"memory": inProcess, "sqlite": inProcessSQLite} {
		t.Run(name, func(t *testing.T) { storetest.RunSuites(t, func(t *testing.T) store.Store { return f(t) }, "Logs") })
	}
}
