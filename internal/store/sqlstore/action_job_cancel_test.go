package sqlstore

import (
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	"testing"
)

func TestActionJobReadCancel(t *testing.T) {
	for name, fresh := range dialectsUnderTest(t) {
		t.Run(name, func(t *testing.T) { storetest.TestActionJobReadCancel(t, fresh(t)) })
	}
}
