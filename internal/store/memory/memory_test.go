package memory_test

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestConformance(t *testing.T) {
	newStore := func(*testing.T) store.Store { return memory.New() }
	storetest.Run(t, newStore)
	storetest.RunSuites(t, newStore, "DeviceCodes", "TenantDeviceFlow")
}
