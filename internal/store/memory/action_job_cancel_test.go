package memory_test

import (
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestActionJobReadCancel(t *testing.T) {
	s := memory.New()
	defer s.Close()
	storetest.TestActionJobReadCancel(t, s)
}
