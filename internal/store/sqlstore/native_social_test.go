package sqlstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"strings"
	"testing"
)

func TestNativeSocialMigrationLeavesClients(t *testing.T) {
	for name, mk := range dsnsUnderTest(t) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			s := openAtVersion(t, mk(t), 36)
			c := &store.Client{TenantID: "t", ClientID: "legacy", Name: "Legacy", IsFirstParty: true, Mobile: &store.ClientMobile{IOS: &store.ClientMobileIOS{AppBundleIdentifier: "com.example.legacy"}}}
			args, err := clientArgs(c)
			if err != nil {
				t.Fatal(err)
			}
			cols, _, _ := strings.Cut(clientCols, ", native_social_login")
			args = args[:strings.Count(cols, ",")+1]
			mustExec(t, s, "INSERT INTO clients ("+cols+") VALUES ("+strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")+")", args...)
			if err = s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			got, err := s.Clients().Get(ctx, "t", "legacy")
			if err != nil || got.Name != "Legacy" || got.Mobile.IOS.AppBundleIdentifier != "com.example.legacy" || got.NativeSocialLogin != nil {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
}
