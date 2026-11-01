package sqlstore

import (
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestJobSweepOutcomes(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.JobSweepOutcomes(t, func(t *testing.T) store.Store { return fresh(t) }) })
	}
}
