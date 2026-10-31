package memory_test

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestJobSweepOutcomes(t *testing.T) {
	storetest.JobSweepOutcomes(t, func(*testing.T) store.Store { return memory.New() })
}
