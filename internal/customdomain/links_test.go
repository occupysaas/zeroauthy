package customdomain_test

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
)

func TestCheckOrigin(t *testing.T) {
	const canonical, alias = "https://acme.auth.example.test", "https://login.acme.test"
	for _, tc := range []struct {
		stored, request string
		ok              bool
	}{
		{alias, alias, true},
		{canonical, canonical, true},
		{"", canonical, true}, // legacy rows mean the pinned canonical origin
		{"", alias, false},    // never the first presenter's host
		{alias, canonical, false},
		{canonical, alias, false},
		{"", "", false},
	} {
		err := customdomain.CheckOrigin(tc.stored, canonical, tc.request)
		if (err == nil) != tc.ok || err != nil && !errors.Is(err, customdomain.ErrOriginMismatch) {
			t.Errorf("CheckOrigin(%q, %q) = %v", tc.stored, tc.request, err)
		}
	}
	if err := customdomain.CheckOrigin("", "", "https://x.test"); err == nil {
		t.Error("legacy row on a tenant without canonical identity accepted")
	}
}

func TestManagedNotificationOriginRequiresLiveCertificate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.clk.set(time.Now())
	d := f.create(t, "acme", "login.acme.test", customdomain.TypeManaged)
	asset := &store.TLSAsset{Key: "cert/live", Kind: store.TLSAssetCertificate, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, PublicData: store.TLSPublicData{Version: 1, NotBefore: f.clk.now().Add(-time.Hour), NotAfter: f.clk.now().Add(time.Hour)}}
	if err := f.st.TLSAssets().Put(ctx, asset, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.st.WithTx(ctx, func(tx store.Store) error {
		return customdomain.ActivateManaged(ctx, tx, d, asset.Key, f.clk.now(), f.clk.now().Add(30*time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetDefault(ctx, "acme", d.Domain); err != nil {
		t.Fatal(err)
	}
	asset, _ = f.st.TLSAssets().Get(ctx, asset.Key)
	asset.PublicData.NotAfter = time.Now().Add(-time.Second)
	if err := f.st.TLSAssets().Put(ctx, asset, asset.Revision); err != nil {
		t.Fatal(err)
	}
	if host, err := f.svc.NotificationOrigin(ctx, "acme", ""); err != nil || host != "acme.auth.example.test" {
		t.Errorf("implicit expired default = %s, %v", host, err)
	}
	if _, err := customdomain.SelectNotificationOrigin(ctx, f.st, "acme", d.Domain); !errors.Is(err, customdomain.ErrDomainUnavailable) {
		t.Errorf("explicit expired origin = %v", err)
	}
	if err := customdomain.OriginUsable(ctx, f.st, "acme", d.Domain); !errors.Is(err, customdomain.ErrDomainUnavailable) {
		t.Errorf("queued expired origin = %v", err)
	}
	if _, err := f.svc.SetDefault(ctx, "acme", d.Domain); !errors.Is(err, customdomain.ErrNotReady) {
		t.Errorf("expired new default = %v", err)
	}
	if id, err := f.st.CustomDomains().GetDefault(ctx, "acme"); err != nil || id != d.ID {
		t.Errorf("configured pointer lost: %s, %v", id, err)
	}
}
