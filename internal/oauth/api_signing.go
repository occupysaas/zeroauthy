package oauth

import (
	"errors"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// apiSigning returns the algorithm and the opened secret to sign an access
// token for rs with. A nil API, and one with no algorithm, is RS256. Only
// HS256 has a secret; one that cannot be opened is an error rather than a
// token signed another way.
func (h *Handlers) apiSigning(rs *store.ResourceServer) (alg string, secret []byte, err error) {
	if rs == nil || rs.SigningAlg == "" {
		return "RS256", nil, nil
	}
	if rs.SigningAlg != "HS256" {
		return rs.SigningAlg, nil, nil
	}
	if len(rs.SigningSecretSealed) == 0 {
		return "", nil, errors.New("oauth: the HS256 API has no signing secret")
	}
	secret, err = keys.OpenAPISigningSecret(h.Wrapper, rs.TenantID, rs.ID, rs.SigningSecretSealed)
	if err != nil {
		return "", nil, errors.New("oauth: open the API signing secret")
	}
	return "HS256", secret, nil
}
