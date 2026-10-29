package sqlstore

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

// Run explicitly once the SQL implementation lands; the unavailable stub fails
// these cases rather than silently selecting no conformance tests.
func TestOrganizationsII(t *testing.T) {
	for name, mk := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			storetest.RunSuites(t, func(t *testing.T) store.Store { return mk(t) }, "OrganizationsII")
		})
	}
}
