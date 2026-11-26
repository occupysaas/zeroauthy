package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/cimd"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// A seed CIMD client whose document cannot be fetched is a warning; the
// deployment starts without it.
func TestRegisterSeedCIMDWarns(t *testing.T) {
	ctx := context.Background()
	st := memory.New()
	defer st.Close()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "ten", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(io.MultiWriter(&buf), nil))
	reg := &cimd.Registrar{Store: st, Fetcher: cimd.NewFetcher(federation.NetworkPolicy{AllowAddr: func(netip.Addr) bool { return false }})}
	registerSeedCIMD(ctx, st, reg, map[string][]string{"a": {"https://agent.invalid/client.json"}, "missing": {"https://x.example/c"}}, log)
	cs, _, _ := st.Clients().List(ctx, "ten", store.ClientFilter{}, store.Page{})
	if len(cs) != 0 || !strings.Contains(buf.String(), "seed CIMD client not registered") || !strings.Contains(buf.String(), "tenant not found") {
		t.Fatalf("clients %d, log %s", len(cs), buf.String())
	}
}
