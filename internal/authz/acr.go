package authz

import (
	"github.com/zeroauthy/zeroauthy/internal/claims"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenantrules"
	"slices"
)

func requestedACR(req Request, t *store.Tenant) string {
	if !slices.Contains(tenantrules.ACRValuesSupported(t), claims.ACRMultiFactor) {
		return ""
	}
	parsed, _ := claims.ParseRequest(req.Claims)
	if claims.RequestsMFA(req.ACRValues, parsed) {
		return claims.ACRMultiFactor
	}
	return ""
}
