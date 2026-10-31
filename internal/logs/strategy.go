package logs

import (
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// StrategyType uses the connection classification shared by organization policy.
// Unknown strategies have no trustworthy classification and remain omitted.
func StrategyType(strategy string) string {
	switch {
	case strategy == store.StrategyDatabase:
		return "database"
	case rules.IsSocial(strategy):
		return "social"
	case rules.IsFederated(strategy):
		return "enterprise"
	default:
		return ""
	}
}
