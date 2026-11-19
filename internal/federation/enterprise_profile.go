package federation

import (
	"encoding/json"
	"fmt"
)

// mappedProfile keeps the stable upstream subject outside the attribute map.
// Custom attributes use ProviderData, which the API projects as profileData
// without changing the primary/linked identity ownership marker.
func mappedProfile(cfg Config, connectionID, sub string, claims, info map[string]any, tokens TokenSet) (Profile, error) {
	compiled, e := CompileAttrMap(cfg.AttrMap, cfg.Strategy, cfg.Channel)
	if e != nil {
		return Profile{}, e
	}
	if compiled == nil || cfg.AttrMap.Mode == "basic_profile" {
		return profileFromClaims(sub, claims)
	}
	tokenSet := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		tokenSet[k] = v
	}

	root, extra := compiled.Apply(MapContext{TokenSet: tokenSet, UserInfo: info, ConnectionID: connectionID, Strategy: cfg.Strategy})
	b, e := json.Marshal(extra)
	if e != nil || len(b) > maxMetadataBytes || depth(extra) > maxMetadataDepth || hasPollution(extra) {
		return Profile{}, fmt.Errorf("%w: mapped profile exceeds limits or contains reserved keys", ErrProfile)
	}
	profile, e := profileFromClaims(sub, root)
	if e != nil {
		return Profile{}, e
	}
	profile.ProviderData = extra
	return profile, nil
}
