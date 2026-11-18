package resourceview

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestAppleIdentityProfileData(t *testing.T) {
	id := store.Identity{Provider: "apple", UserID: "sub", ProviderData: map[string]any{"is_private_email": true}}
	view := Identity(&id)
	data, ok := view["profileData"].(map[string]any)
	if !ok || data["is_private_email"] != true || id.Linked() || view["isSocial"] != true {
		t.Fatalf("%+v", view)
	}
}
