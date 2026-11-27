package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/federation/providers"
)

func init() {
	socialHooks[providers.HookFacebook] = socialHook{decorate: facebookAppSecretProof}
	socialHooks[providers.HookLinkedIn] = socialHook{begin: linkedinVersion}
}

// facebookAppSecretProof adds appsecret_proof, HMAC-SHA256 of the access
// token keyed with the app secret, to every Graph call. The proof is a
// credential: it travels only in the outbound query and never in an error.
func facebookAppSecretProof(req *http.Request, accessToken, clientSecret string) {
	mac := hmac.New(sha256.New, []byte(clientSecret))
	mac.Write([]byte(accessToken))
	q := req.URL.Query()
	q.Set("appsecret_proof", hex.EncodeToString(mac.Sum(nil)))
	req.URL.RawQuery = q.Encode()
}

// linkedinVersion refuses strategy_version 1 and 2 at login: LinkedIn retired
// those APIs (LR39b-6, SP-8). They stay stored and returned.
func linkedinVersion(_ *providers.Descriptor, cfg Config, _ string, _ *Endpoints) error {
	if cfg.Social == nil || cfg.Social.StrategyVersion != 3 {
		return fmt.Errorf("%w: linkedin strategy_version 1 and 2 are retired; use 3", ErrConnectionUnusable)
	}
	return nil
}
