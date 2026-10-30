package memory

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
)

func TestOrganizationSearchParity(t *testing.T) {
	storetest.OrganizationSearchParity(t, func(t *testing.T) store.Store { return New() })
}
