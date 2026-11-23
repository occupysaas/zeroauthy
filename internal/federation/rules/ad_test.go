package rules

import (
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"strings"
	"testing"
)

func TestParseAD(t *testing.T) {
	certPEM := samlCert(t)
	block, _ := pem.Decode([]byte(certPEM))
	der := base64.StdEncoding.EncodeToString(block.Bytes)
	s, errs := Parse(Input{Strategy: AD, Name: "corp", RootAttributes: SyncOnFirstLogin, Options: map[string]any{
		"tenant_domain": "Corp.Example.Test", "domain_aliases": []any{"corp.example.test", "example.org"},
		"ips": []any{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"}, "kerberos": true, "certAuth": false,
		"disable_cache": true, "disable_self_service_change_password": true, "icon_url": "https://corp.example.test/i.png",
		"upstream_params": map[string]any{}, "non_persistent_attrs": []any{"groups"},
		"agentIP": "198.51.100.4", "agentMode": true, "agentVersion": "8.0.5", "signInEndpoint": "http://connector.corp:4000/wsfed",
		"certs": []any{der, certPEM},
	}})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	a := s.AD
	if a == nil || a.TenantDomain != "corp.example.test" || !a.Kerberos || a.CertAuth || !a.DisableChangePassword ||
		a.SignInEndpoint != "http://connector.corp:4000/wsfed" || len(a.Certs) != 2 || len(a.Thumbprints) != 2 || len(a.Thumbprints[0]) != 40 ||
		len(a.Thumbprints384[1]) != 96 || s.ProfileSync != SyncOnFirstLogin || strings.Join(s.DomainAliases, ",") != "corp.example.test,example.org" ||
		!IsEnterprise(AD) || !IsFederated(AD) || IsSocial(AD) {
		t.Fatalf("settings %+v %+v", s, a)
	}
	if len(a.IPs) != 3 || !ADClientInRanges("10.1.2.3", a.IPs) || !ADClientInRanges("192.0.2.7", a.IPs) || ADClientInRanges("192.0.2.8", a.IPs) ||
		!ADClientInRanges("2001:db8::1", a.IPs) || !ADClientInRanges("::ffff:10.0.0.1", a.IPs) || ADClientInRanges("not-an-ip", a.IPs) {
		t.Fatalf("ranges %v", a.IPs)
	}
	if a.IPs[1] != netip.MustParsePrefix("192.0.2.7/32") {
		t.Fatalf("single address as /32: %v", a.IPs[1])
	}
	// The minimal connection: no options at all.
	if s, errs := Parse(Input{Strategy: AD, Name: "corp"}); len(errs) > 0 || s.AD == nil || s.ProfileSync != SyncOnEachLogin {
		t.Fatalf("minimal: %v", errs)
	}
	for name, opts := range map[string]map[string]any{
		"ip":      {"ips": []any{"10.0.0.0/33"}},
		"ip type": {"ips": "10.0.0.0/8"},
		"too many ips": {"ips": func() []any {
			l := make([]any, 257)
			for i := range l {
				l[i] = "10.0.0.1"
			}
			return l
		}()},
		"kerberos":      {"kerberos": "yes"},
		"tenant_domain": {"tenant_domain": "not a domain"},
		"aliases":       {"domain_aliases": []any{"bad domain"}},
		"cert":          {"certs": []any{"bm90IGEgY2VydA=="}},
		"three certs":   {"certs": []any{der, der, der}},
		"endpoint":      {"signInEndpoint": "ftp://connector/wsfed"},
		"icon":          {"icon_url": 7},
		"upstream":      {"upstream_params": "x"},
		"agentVersion":  {"agentVersion": strings.Repeat("9", 65)},
	} {
		if _, errs := Parse(Input{Strategy: AD, Name: "corp", Options: opts}); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	if _, errs := Parse(Input{Strategy: AD, Name: "co|rp"}); len(errs) == 0 {
		t.Error("| in the name accepted")
	}
	if _, errs := Parse(Input{Strategy: AD, Name: "corp", RootAttributes: "sometimes"}); len(errs) == 0 {
		t.Error("bad set_user_root_attributes accepted")
	}
}
