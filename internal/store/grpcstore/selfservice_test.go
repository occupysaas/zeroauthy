package grpcstore

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// directoryOnly is a backing store with scim.v1 version 1 only.
type directoryOnly struct{ store.Store }

func (directoryOnly) SelfServiceSupported() bool { return false }

// A plugin answering scim.v1 version 1 keeps the directory but has no
// self-service; its calls fail closed without reaching the plugin.
func TestSelfServiceNeedsCapabilityVersion2(t *testing.T) {
	m := memory.New()
	c := serve(t, directoryOnly{m})
	if !store.DirectoryAvailable(c) {
		t.Fatal("directory lost")
	}
	if store.SelfServiceAvailable(c) {
		t.Fatal("version 1 plugin reported self-service")
	}
	_, err := c.SelfService().GetProfile(context.Background(), "t", "ssp_1")
	if !errors.Is(err, store.ErrSelfServiceUnavailable) {
		t.Fatalf("got %v", err)
	}
	if !store.SelfServiceAvailable(serve(t, m)) {
		t.Fatal("version 2 plugin hid self-service")
	}
}

// selfServiceOnly is a backing store with scim.v1 version 2 only.
type selfServiceOnly struct{ store.Store }

func (selfServiceOnly) DirectorySyncSupported() bool { return false }
func (selfServiceOnly) SelfServiceSupported() bool   { return true }

// A plugin answering scim.v1 version 2 keeps self-service but has no
// directory provisioning; its calls fail closed.
func TestDirectorySyncNeedsCapabilityVersion3(t *testing.T) {
	m := memory.New()
	c := serve(t, selfServiceOnly{m})
	if !store.SelfServiceAvailable(c) {
		t.Fatal("self-service lost")
	}
	if store.DirectorySyncAvailable(c) {
		t.Fatal("version 2 plugin reported directory provisioning")
	}
	_, err := c.DirectorySync().GetProvisioning(context.Background(), "t", "con_1")
	if !errors.Is(err, store.ErrDirectorySyncUnavailable) {
		t.Fatalf("got %v", err)
	}
	if !store.DirectorySyncAvailable(serve(t, m)) {
		t.Fatal("version 3 plugin hid directory provisioning")
	}
}
