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

// The process wrapper must forward wsfed.v1 (Plan 37b) the same way.
func TestOpenedForwardsWSFedCapability(t *testing.T) {
	var _ store.WSFedSupporter = (*opened)(nil)
	o := &opened{Store: memory.New()}
	defer o.Store.Close()
	if err := store.CheckWSFedSupport(context.Background(), o); !errors.Is(err, store.ErrWSFedUnavailable) {
		t.Fatalf("wrapper without wsfed.v1: %v", err)
	}
}

// The process wrapper forwards ad_hub.v1 (Plan 38a) to the wrapped store.
func TestOpenedForwardsADHub(t *testing.T) {
	var _ store.ADHubSupporter = (*opened)(nil)
	var _ store.ADHubStore = (*opened)(nil)
	o := &opened{Store: memory.New()}
	defer o.Store.Close()
	ctx := context.Background()
	repo, err := store.ADHub(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetADProvisioning(ctx, "t", "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetADProvisioning through the wrapper: %v", err)
	}
}
