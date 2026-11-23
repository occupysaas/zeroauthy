package mgmt_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/samlcore"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

func wsfedMetadata(t *testing.T, certPEM string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(samlcore.BuildWSFedMetadata("http://adfs.example.test/adfs/services/trust", "https://adfs.example.test/adfs/ls/", []*x509.Certificate{parsed}))
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// adfs connections take the sign-in endpoint and thumbprints from the
// metadata (fedMetadataXml or adfs_server); written values are replaced.
func TestADFSConnectionManagement(t *testing.T) {
	e := keysEnv(t)
	md := string(wsfedMetadata(t, samlTestCert(t)))
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "corp-adfs", "strategy": "adfs",
		"options": map[string]any{"fedMetadataXml": md, "thumbprints": []string{"client-sent"}, "signInEndpoint": "https://evil.example.test/",
			"prev_thumbprints": []string{strings.Repeat("ab", 20)}}}, e.h.CreateConnection)
	if r.Code != 201 {
		t.Fatalf("create: %d %v", r.Code, v)
	}
	opts := v.(map[string]any)["options"].(map[string]any)
	tp, _ := opts["thumbprints"].([]any)
	if len(tp) != 1 || len(tp[0].(string)) != 40 || opts["signInEndpoint"] != "https://adfs.example.test/adfs/ls/" || opts["prev_thumbprints"] != nil ||
		len(opts["thumbprints_sha384"].([]any)) != 1 {
		t.Fatalf("derived options %v", opts)
	}
	for name, options := range map[string]map[string]any{
		"no source":    {},
		"both sources": {"fedMetadataXml": md, "adfs_server": "adfs.example.test"},
		"not metadata": {"fedMetadataXml": "<a/>"},
	} {
		if r, _ := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "bad-" + strings.ReplaceAll(name, " ", "-"), "strategy": "adfs",
			"options": options}, e.h.CreateConnection); r.Code != 400 {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
}

// adfs_server is fetched through the federation fetcher (host form gets the
// metadata path); a certificate change keeps the old thumbprints as
// prev_thumbprints.
func TestADFSConnectionServer(t *testing.T) {
	e := keysEnv(t)
	current, fetched := wsfedMetadata(t, samlTestCert(t)), ""
	e.h.SAMLMetadata = func(_ context.Context, u string) ([]byte, error) { fetched = u; return current, nil }
	r, v := e.call(t, e.tn, m2mCaller(), "POST", "/connections", map[string]any{"name": "srv-adfs", "strategy": "adfs",
		"options": map[string]any{"adfs_server": "adfs.example.test", "thumbprints": []string{strings.Repeat("ab", 20)}}}, e.h.CreateConnection)
	if r.Code != 201 || fetched != "https://adfs.example.test/FederationMetadata/2007-06/FederationMetadata.xml" {
		t.Fatalf("create: %d %v (fetched %q)", r.Code, v, fetched)
	}
	id := v.(map[string]any)["id"].(string)
	opts := v.(map[string]any)["options"].(map[string]any)
	first, _ := opts["thumbprints"].([]any)
	if len(first) != 1 || first[0] == strings.Repeat("ab", 20) || opts["signInEndpoint"] != "https://adfs.example.test/adfs/ls/" {
		t.Fatalf("derived options %v", opts)
	}
	update := func(body map[string]any) (int, map[string]any) {
		r, v := e.call(t, e.tn, m2mCaller(), "PATCH", "/connections/"+id, body, func(w http.ResponseWriter, r *http.Request) { e.h.UpdateConnection(w, r, id) })
		out, _ := v.(map[string]any)
		return r.Code, out
	}
	current = wsfedMetadata(t, samlTestCert(t))
	code, out := update(map[string]any{"options": map[string]any{"adfs_server": "adfs.example.test"}})
	if code != 200 {
		t.Fatalf("rotate: %d %v", code, out)
	}
	opts = out["options"].(map[string]any)
	if now, _ := opts["thumbprints"].([]any); len(now) != 1 || now[0] == first[0] || !slices.Equal(opts["prev_thumbprints"].([]any), first) {
		t.Fatalf("rotation: %v", opts)
	}
	// Unchanged metadata keeps prev_thumbprints.
	code, out = update(map[string]any{"options": map[string]any{"adfs_server": "adfs.example.test"}})
	if code != 200 || !slices.Equal(out["options"].(map[string]any)["prev_thumbprints"].([]any), first) {
		t.Fatalf("unchanged: %d %v", code, out)
	}
	big := append([]byte("<!-- "), make([]byte, 130<<10)...)
	current = big
	if code, _ := update(map[string]any{"options": map[string]any{"adfs_server": "adfs.example.test"}}); code != 400 {
		t.Fatalf("oversized metadata: %d", code)
	}
}
