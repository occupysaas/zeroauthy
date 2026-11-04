package app

import (
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/ratelimit"
)

// Every limiter group has a security.rate_limit key, and nothing else does.
func TestRateLimitConfigCoversEveryGroup(t *testing.T) {
	keys := config.RateLimit{}.Groups()
	if len(keys) != len(ratelimit.Groups) {
		t.Fatalf("config groups %v, limiter groups %v", keys, ratelimit.Groups)
	}
	for _, g := range ratelimit.Groups {
		if _, ok := keys[string(g)]; !ok {
			t.Errorf("group %s has no config key", g)
		}
	}
	if rateLimit(config.RateLimit{Enabled: false}) != nil {
		t.Error("disabled config built a limiter")
	}
	if rateLimit(config.RateLimit{Enabled: true, MaxTrackedKeys: 1, Token: config.RateLimitGroup{Rate: 1, Burst: 1}}) == nil {
		t.Error("enabled config built no limiter")
	}
}
