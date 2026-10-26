package customdomain_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
)

// zone is a tiny authoritative-style answerer: it returns the CNAME chain it
// knows (like a recursive resolver), records at the end and optional padding.
type zone struct {
	cname   map[string]string
	txt     map[string][][]string // name → RRs → chunks
	a       map[string][]netip.Addr
	silent  map[string]bool // never answer
	padding int             // bytes of additional TXT padding per response
}

func serveZone(t *testing.T, z *zone) *customdomain.BoundedResolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			name := strings.ToLower(q.Questions[0].Name.String())
			if z.silent[name] {
				continue
			}
			resp := z.answer(q)
			if out, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	return &customdomain.BoundedResolver{Server: pc.LocalAddr().String(), Timeout: 300 * time.Millisecond}
}

func (z *zone) answer(q dnsmessage.Message) dnsmessage.Message {
	question := q.Questions[0]
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
	name := strings.ToLower(question.Name.String())
	hdr := func(n string, typ dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(n), Type: typ, Class: dnsmessage.ClassINET, TTL: 60}
	}
	seen := map[string]bool{}
	for target, ok := z.cname[name]; ok && !seen[name]; target, ok = z.cname[name] {
		seen[name] = true
		resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)}})
		name = target
	}
	found := false
	switch question.Type {
	case dnsmessage.TypeTXT:
		for _, chunks := range z.txt[name] {
			found = true
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: chunks}})
		}
	case dnsmessage.TypeA:
		for _, ip := range z.a[name] {
			if ip.Is4() {
				found = true
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(name, dnsmessage.TypeA), Body: &dnsmessage.AResource{A: ip.As4()}})
			}
		}
	}
	_, known := z.txt[name]
	if !found && len(resp.Answers) == 0 && !known && z.a[name] == nil {
		resp.RCode = dnsmessage.RCodeNameError
	}
	for left := z.padding; left > 0; left -= 250 {
		resp.Additionals = append(resp.Additionals, dnsmessage.Resource{Header: hdr("pad.test.", dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{strings.Repeat("x", 250)}}})
	}
	return resp
}

func TestBoundedResolver(t *testing.T) {
	ctx := context.Background()
	chain := map[string]string{}
	for i := range 9 {
		if i < 8 {
			chain[fmt.Sprintf("hop%d.test.", i)] = fmt.Sprintf("hop%d.test.", i+1)
		}
		chain[fmt.Sprintf("long%d.test.", i)] = fmt.Sprintf("long%d.test.", i+1)
	}
	chain["loop-a.test."], chain["loop-b.test."] = "loop-b.test.", "loop-a.test."
	chain["alias.test."] = "chunks.test."
	z := &zone{
		cname: chain,
		txt: map[string][][]string{
			"chunks.test.": {{"zeroauthy-", "domain"}, {"other"}},
			"hop8.test.":   {{"eight"}},
			"long9.test.":  {{"nine"}},
		},
		a:      map[string][]netip.Addr{"ip.test.": {netip.MustParseAddr("192.0.2.1")}},
		silent: map[string]bool{"slow.test.": true},
	}
	r := serveZone(t, z)

	// Chunks of one RR join; separate RRs stay separate.
	got, err := r.LookupTXT(ctx, "alias.test")
	if err != nil || !slices.Equal(got, []string{"zeroauthy-domain", "other"}) {
		t.Fatalf("chunks = %q, %v", got, err)
	}
	if got, err := r.LookupTXT(ctx, "hop1.test"); err != nil || !slices.Equal(got, []string{"eight"}) {
		t.Fatalf("seven hops = %q, %v", got, err)
	}
	if got, err := r.LookupTXT(ctx, "hop0.test"); err != nil || !slices.Equal(got, []string{"eight"}) {
		t.Fatalf("eight hops = %q, %v", got, err)
	}
	if _, err := r.LookupTXT(ctx, "long0.test"); !errors.Is(err, customdomain.ErrDNSLimit) {
		t.Fatalf("nine hops = %v", err)
	}
	if _, err := r.LookupTXT(ctx, "loop-a.test"); !errors.Is(err, customdomain.ErrDNSLimit) {
		t.Fatalf("loop = %v", err)
	}
	if _, err := r.LookupTXT(ctx, "missing.test"); !errors.Is(err, customdomain.ErrDNSNotFound) {
		t.Fatalf("nxdomain = %v", err)
	}
	if _, err := r.LookupTXT(ctx, "ip.test"); !errors.Is(err, customdomain.ErrDNSNotFound) {
		t.Fatalf("nodata = %v", err)
	}
	start := time.Now()
	if _, err := r.LookupTXT(ctx, "slow.test"); err == nil || errors.Is(err, customdomain.ErrDNSNotFound) || time.Since(start) > 2*time.Second {
		t.Fatalf("deadline = %v after %s", err, time.Since(start))
	}
	if ips, err := r.LookupNetIP(ctx, "ip4", "ip.test"); err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("ip = %v, %v", ips, err)
	}
	if final, err := r.LookupCNAME(ctx, "alias.test"); err != nil || final != "chunks.test" {
		t.Fatalf("cname = %q, %v", final, err)
	}
}

// Accumulated response bytes across hops are bounded at 64 KiB.
func TestBoundedResolverSize(t *testing.T) {
	ctx := context.Background()
	z := &zone{cname: map[string]string{}, txt: map[string][][]string{"end.test.": {{"v"}}}, padding: 20000}
	r := serveZone(t, z)
	if got, err := r.LookupTXT(ctx, "end.test"); err != nil || !slices.Equal(got, []string{"v"}) {
		t.Fatalf("small = %q, %v", got, err)
	}
	// The local answerer returns whole chains, so split the chain with a
	// missing link: each hop forces a fresh, padded response.
	r2 := serveZone(t, &zone{cname: map[string]string{"a.test.": "b.test."}, txt: map[string][][]string{}, padding: 40000})
	if _, err := r2.LookupTXT(ctx, "a.test"); !errors.Is(err, customdomain.ErrDNSLimit) {
		t.Fatalf("oversize = %v", err)
	}
}

func TestSystemResolver(t *testing.T) {
	for conf, want := range map[string]string{
		"# c\nsearch x\nnameserver 192.0.2.53\nnameserver 192.0.2.54\n": "192.0.2.53:53",
		"nameserver 2001:db8::53\n":                                     "[2001:db8::53]:53",
		"nameserver fe80::1%eth0\nnameserver 192.0.2.9\n":               "192.0.2.9:53",
		"search only\n": "",
	} {
		got, err := customdomain.ParseResolvConf(strings.NewReader(conf))
		if got != want || (want == "") != (err != nil) {
			t.Errorf("%q = %q, %v", conf, got, err)
		}
	}
}
