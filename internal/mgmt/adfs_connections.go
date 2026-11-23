package mgmt

import (
	"context"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/samlcore"
)

// adfsReadOnly are the adfs options derived from the metadata (Plan 37b);
// values a caller writes are replaced.
var adfsReadOnly = []string{"signInEndpoint", "thumbprints", "thumbprints_sha384", "prev_thumbprints"}

// fetchADFSMetadata fetches and reads an adfs_server's federation metadata
// (at most 128 KB, Auth0's limit). It makes an outbound request, so callers
// run it outside store transactions. "" fetches nothing.
func (h *Handlers) fetchADFSMetadata(ctx context.Context, server string) (map[string]any, error) {
	if server == "" {
		return nil, nil
	}
	if h.SAMLMetadata == nil {
		return nil, badBody("options.adfs_server cannot be fetched by this server")
	}
	u := rules.ADFSMetadataURL(server)
	if err := rules.ValidateEndpoint(u, false); err != nil {
		return nil, badBody("options.adfs_server must be a public host or https URL")
	}
	raw, err := h.SAMLMetadata(ctx, u)
	if err != nil {
		return nil, badBody("options.adfs_server metadata could not be fetched")
	}
	if len(raw) > rules.MaxADFSMetadataBytes {
		return nil, badBody("Federation metadata document exceeds the maximum allowed size of 128 KB")
	}
	md, err := samlcore.ParseWSFedMetadata(raw)
	if err != nil {
		return nil, badBody("options.adfs_server metadata is not WS-Federation metadata with a signing certificate")
	}
	var t1, t384 []any
	for _, c := range md.SigningCerts {
		s1, s384 := rules.ADFSThumbprints(c.Raw)
		t1, t384 = append(t1, s1), append(t384, s384)
	}
	return map[string]any{"signInEndpoint": md.PassiveEndpoint, "thumbprints": t1, "thumbprints_sha384": t384}, nil
}

// prepareADFS replaces the read-only adfs options of an options write with
// what the metadata gives: derived (from adfs_server) or nothing (from
// fedMetadataXml, which the rules read). prev is the stored connection's
// options on update, nil on create.
func prepareADFS(spec *connrules.Spec, derived map[string]any) {
	if spec.Strategy != rules.ADFS || spec.Options.Extra == nil {
		return
	}
	for _, k := range adfsReadOnly {
		delete(spec.Options.Extra, k)
	}
	for k, v := range derived {
		spec.Options.Extra[k] = v
	}
}

// rotateADFS keeps the previous thumbprints trusted after the metadata's
// certificates change (prev_thumbprints), once spec is normalized.
func rotateADFS(spec *connrules.Spec, prev map[string]any) {
	if spec.Strategy != rules.ADFS || spec.Options.Extra == nil {
		return
	}
	old := anyStrings(prev["thumbprints"])
	now := anyStrings(spec.Options.Extra["thumbprints"])
	switch {
	case len(old) > 0 && !slices.Equal(old, now):
		spec.Options.Extra["prev_thumbprints"] = prev["thumbprints"]
	case prev["prev_thumbprints"] != nil:
		spec.Options.Extra["prev_thumbprints"] = prev["prev_thumbprints"]
	}
}

func anyStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = t
	}
	return out
}
