package storeplugin

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// The process wrapper must forward saml.v1: a wrapped store that cannot
// report the capability is unavailable, never assumed supported.
func TestOpenedForwardsSAMLCapability(t *testing.T) {
	var _ store.SAMLSupporter = (*opened)(nil)
	o := &opened{Store: memory.New()}
	defer o.Store.Close()
	if err := store.CheckSAMLSupport(context.Background(), o); !errors.Is(err, store.ErrSAMLUnavailable) {
		t.Fatalf("wrapper without saml.v1: %v", err)
	}
}
