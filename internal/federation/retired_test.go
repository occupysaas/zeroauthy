package federation

import (
	"errors"
	"strings"
	"testing"
)

// TestRetiredProviders (Review Focus 4): fitbit and instagram are accepted
// and stored like any connection, but login start refuses them with the
// provider's reason and no upstream call; LinkedIn's version refusal stays.
func TestRetiredProviders(t *testing.T) {
	for strategy, reason := range map[string]string{"fitbit": "Google Health API", "instagram": "Basic Display"} {
		t.Run(strategy, func(t *testing.T) {
			cfg := socConfig(t, strategy, `,"scope":["profile"]`)
			f := newSocFixture(t)
			ps := f.providers()
			_, err := ps.SocialEndpoints(cfg, "")
			if !errors.Is(err, ErrConnectionUnusable) || !strings.Contains(err.Error(), reason) {
				t.Fatalf("err %v", err)
			}
			e := newSocFlowEnv(t, f, strategy, nil)
			if _, err := e.begin(t, ""); !errors.Is(err, ErrConnectionUnusable) {
				t.Fatalf("begin %v", err)
			}
			for path, n := range f.calls {
				t.Fatalf("upstream call %s ×%d", path, n)
			}
		})
	}
	if _, err := NewProviders(NetworkPolicy{}, nil).SocialEndpoints(socConfig(t, "linkedin", `,"strategy_version":2`), ""); !errors.Is(err, ErrConnectionUnusable) {
		t.Fatalf("linkedin v2: %v", err)
	}
}
