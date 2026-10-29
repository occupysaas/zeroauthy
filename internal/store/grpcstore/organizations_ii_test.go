package grpcstore

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

// Run explicitly after capability/codecs land. The unavailable stub must not
// masquerade as an implemented OrganizationsII capability.
func TestOrganizationsII(t *testing.T) {
	storetest.RunSuites(t, func(t *testing.T) store.Store { return serve(t, memory.New()) }, "OrganizationsII")
}
