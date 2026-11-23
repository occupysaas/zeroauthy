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
