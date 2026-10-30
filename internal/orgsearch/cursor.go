package orgsearch

import (
	"encoding/base64"
	"encoding/json"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Cursor binding uses the existing stable server wrapper rather than a random
// process key. Recreating a handler with the same master key preserves cursors.
// Cursors are positions, not snapshots; concurrent writes may move rows.
func cursorFields(tid, parser, sort string, q store.OrganizationQuery) []string {
	if parser == "" {
		parser = "lucene"
	}
	raw, _ := json.Marshal(q)
	return []string{tid, parser, sort, string(raw)}
}
func EncodeCursor(w keys.Wrapper, tid, parser string, q store.OrganizationQuery, p store.OrganizationSearchPage) (string, error) {
	p, e := Page(p)
	if e != nil || p.LastID == "" || Validate(q) != nil {
		return "", store.ErrInvalid
	}
	raw, _ := json.Marshal([]string{p.LastValue, p.LastID})
	sealed, e := keys.SealBound(w, "organization-search-cursor-v1", cursorFields(tid, parser, p.Sort, q), raw)
	if e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}
func DecodeCursor(w keys.Wrapper, token, tid, parser string, q store.OrganizationQuery, p store.OrganizationSearchPage) (store.OrganizationSearchPage, error) {
	p, e := Page(p)
	if e != nil || len(token) > 10000 || Validate(q) != nil {
		return p, store.ErrInvalid
	}
	sealed, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil {
		return p, store.ErrInvalid
	}
	raw, e := keys.OpenBound(w, "organization-search-cursor-v1", cursorFields(tid, parser, p.Sort, q), sealed)
	if e != nil {
		return p, store.ErrInvalid
	}
	var tuple []string
	if json.Unmarshal(raw, &tuple) != nil || len(tuple) != 2 || tuple[1] == "" {
		return p, store.ErrInvalid
	}
	p.LastValue, p.LastID = tuple[0], tuple[1]
	return Page(p)
}
