package sqlstore

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

// Task 4 supplies the implementation; this suite must not be reported passing
// while Logs returns UnimplementedLogs.
func TestLogs(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.RunSuites(t, func(t *testing.T) store.Store { return fresh(t) }, "Logs") })
	}
}
