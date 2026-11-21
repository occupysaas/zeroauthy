package claims

import (
	"slices"
	"strings"
)

func RequestsMFA(acrValues string, req *Request) bool {
	if slices.Contains(strings.Fields(acrValues), ACRMultiFactor) {
		return true
	}
	if req == nil {
		return false
	}
	acr := req.IDToken["acr"]
	if acr == nil || !acr.Essential {
		return false
	}
	if value, ok := acr.Value.(string); ok && value == ACRMultiFactor {
		return true
	}
	for _, value := range acr.Values {
		if value == ACRMultiFactor {
			return true
		}
	}
	return false
}
