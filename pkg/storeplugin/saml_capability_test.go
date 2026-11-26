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

// The process wrapper must forward scim.v1 version 3 (Plan 37c Phase C).
func TestOpenedForwardsDirectorySyncCapability(t *testing.T) {
	var _ store.DirectorySyncSupporter = (*opened)(nil)
	o := &opened{Store: noDirectorySync{memory.New()}}
	defer o.Store.Close()
	if store.DirectorySyncAvailable(o) {
		t.Fatal("wrapper without directory provisioning reported support")
	}
	if !store.DirectorySyncAvailable(&opened{Store: memory.New()}) {
		t.Fatal("wrapper hid directory provisioning")
	}
}

type noDirectorySync struct{ store.Store }

func (noDirectorySync) DirectorySyncSupported() bool { return false }

// The process wrapper forwards my_org.v1 (Plan 42b) to the wrapped store.
func TestOpenedForwardsMyOrg(t *testing.T) {
	var _ store.MyOrgSupporter = (*opened)(nil)
	var _ store.MyOrgStore = (*opened)(nil)
	o := &opened{Store: memory.New()}
	defer o.Store.Close()
	ctx := context.Background()
	repo, err := store.MyOrg(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetMyOrgClientConfig(ctx, "t", "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetMyOrgClientConfig through the wrapper: %v", err)
	}
}
