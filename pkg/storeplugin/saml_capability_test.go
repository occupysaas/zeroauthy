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

// The process wrapper must forward scim.v1 (Plan 37c): a wrapped store that
// cannot report it is unavailable.
func TestOpenedForwardsDirectoryCapability(t *testing.T) {
	var _ store.DirectorySupporter = (*opened)(nil)
	o := &opened{Store: noDirectory{memory.New()}}
	defer o.Store.Close()
	if store.DirectoryAvailable(o) {
		t.Fatal("wrapper without scim.v1 reported support")
	}
	if !store.DirectoryAvailable(&opened{Store: memory.New()}) {
		t.Fatal("wrapper hid scim.v1")
	}
}

type noDirectory struct{ store.Store }

func (noDirectory) DirectorySupported() bool { return false }

// The process wrapper must forward scim.v1 version 2 (Plan 37c Phase B).
func TestOpenedForwardsSelfServiceCapability(t *testing.T) {
	var _ store.SelfServiceSupporter = (*opened)(nil)
	o := &opened{Store: noSelfService{memory.New()}}
	defer o.Store.Close()
	if store.SelfServiceAvailable(o) {
		t.Fatal("wrapper without self-service reported support")
	}
	if !store.SelfServiceAvailable(&opened{Store: memory.New()}) {
		t.Fatal("wrapper hid self-service")
	}
}

type noSelfService struct{ store.Store }

func (noSelfService) SelfServiceSupported() bool { return false }
