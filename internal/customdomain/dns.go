package customdomain

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// DNS proof budgets (design §5): one total deadline, eight CNAME hops and 64 KiB
// of accumulated responses per lookup.
const (
	dnsDeadline = 5 * time.Second
	dnsMaxHops  = 8
	dnsMaxBytes = 64 << 10
)

var (
	// ErrDNSNotFound is a definite answer: NXDOMAIN or no records of the type.
	ErrDNSNotFound = errors.New("customdomain: DNS name has no such records")
	// ErrDNSLimit means a CNAME loop, too many hops or too large a response.
	ErrDNSLimit = errors.New("customdomain: DNS lookup exceeded its limits")
)

// DNSResolver is the bounded resolver used for ownership proof. Production uses
// BoundedResolver against the deployment's resolver; never a tenant's.
type DNSResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
	LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error)
}

// BoundedResolver speaks DNS directly to Server (host:port) so every CNAME hop
// and response byte is counted, unlike an opaque system lookup.
type BoundedResolver struct {
	Server  string
	Timeout time.Duration // zero means the five-second proof deadline
	Dialer  net.Dialer
}

type dnsBudget struct{ hops, bytes int }

func (r *BoundedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	rrs, _, err := r.resolve(ctx, name, dnsmessage.TypeTXT)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		// Chunks of one RR form one value; different RRs never combine.
		out = append(out, strings.Join(rr.Body.(*dnsmessage.TXTResource).TXT, ""))
	}
	return out, nil
}

// LookupCNAME follows the chain and returns its final name, like net.LookupCNAME.
func (r *BoundedResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	_, final, err := r.resolve(ctx, name, dnsmessage.TypeA)
	if err != nil && !errors.Is(err, ErrDNSNotFound) {
		return "", err
	}
	if final == "" {
		return "", ErrDNSNotFound
	}
	return final, nil
}

func (r *BoundedResolver) LookupNetIP(ctx context.Context, network, name string) ([]netip.Addr, error) {
	var types []dnsmessage.Type
	switch network {
	case "ip":
		types = []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}
	case "ip4":
		types = []dnsmessage.Type{dnsmessage.TypeA}
	case "ip6":
		types = []dnsmessage.Type{dnsmessage.TypeAAAA}
	default:
		return nil, fmt.Errorf("customdomain: unsupported network %q", network)
	}
	var out []netip.Addr
	for _, t := range types {
		rrs, _, err := r.resolve(ctx, name, t)
		if errors.Is(err, ErrDNSNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, rr := range rrs {
			switch b := rr.Body.(type) {
			case *dnsmessage.AResource:
				out = append(out, netip.AddrFrom4(b.A))
			case *dnsmessage.AAAAResource:
				out = append(out, netip.AddrFrom16(b.AAAA))
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrDNSNotFound
	}
	return out, nil
}

// resolve returns the records of qtype at the end of name's CNAME chain and
// that chain's final name ("" when name itself has no CNAME).
func (r *BoundedResolver) resolve(ctx context.Context, name string, qtype dnsmessage.Type) ([]dnsmessage.Resource, string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = dnsDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	b := &dnsBudget{}
	target := strings.ToLower(strings.TrimSuffix(name, ".")) + "."
	final := ""
	for {
		msg, err := r.exchange(ctx, b, target, qtype)
		if err != nil {
			return nil, final, err
		}
		if msg.RCode == dnsmessage.RCodeNameError {
			return nil, final, ErrDNSNotFound
		}
		if msg.RCode != dnsmessage.RCodeSuccess {
			return nil, final, fmt.Errorf("customdomain: DNS server answered %v", msg.RCode)
		}
		// Follow the chain within this response before asking again.
		followed := false
		for {
			var found []dnsmessage.Resource
			next := ""
			for _, rr := range msg.Answers {
				if !strings.EqualFold(rr.Header.Name.String(), target) {
					continue
				}
				if rr.Header.Type == qtype {
					found = append(found, rr)
				} else if c, ok := rr.Body.(*dnsmessage.CNAMEResource); ok && next == "" {
					next = strings.ToLower(c.CNAME.String())
				}
			}
			if len(found) > 0 {
				return found, final, nil
			}
			if next == "" {
				break
			}
			if b.hops++; b.hops > dnsMaxHops {
				return nil, final, ErrDNSLimit
			}
			target, final, followed = next, strings.TrimSuffix(next, "."), true
		}
		if !followed {
			return nil, final, ErrDNSNotFound
		}
	}
}

func (r *BoundedResolver) exchange(ctx context.Context, b *dnsBudget, name string, qtype dnsmessage.Type) (*dnsmessage.Message, error) {
	qname, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, ErrDNSLimit
	}
	var idb [2]byte
	if _, err := io.ReadFull(rand.Reader, idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q := dnsmessage.Question{Name: qname, Type: qtype, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}).Pack()
	if err != nil {
		return nil, err
	}
	raw, err := r.roundTrip(ctx, "udp", query)
	if err != nil {
		return nil, err
	}
	msg, err := r.account(b, raw, id, q)
	if err == nil && msg.Truncated {
		if raw, err = r.roundTrip(ctx, "tcp", query); err != nil {
			return nil, err
		}
		msg, err = r.account(b, raw, id, q)
	}
	return msg, err
}

func (r *BoundedResolver) account(b *dnsBudget, raw []byte, id uint16, q dnsmessage.Question) (*dnsmessage.Message, error) {
	if b.bytes += len(raw); b.bytes > dnsMaxBytes {
		return nil, ErrDNSLimit
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(raw); err != nil {
		return nil, fmt.Errorf("customdomain: malformed DNS response: %w", err)
	}
	if msg.ID != id || !msg.Response || len(msg.Questions) != 1 || msg.Questions[0].Type != q.Type ||
		!strings.EqualFold(msg.Questions[0].Name.String(), q.Name.String()) {
		return nil, errors.New("customdomain: mismatched DNS response")
	}
	return &msg, nil
}

func (r *BoundedResolver) roundTrip(ctx context.Context, network string, query []byte) ([]byte, error) {
	conn, err := r.Dialer.DialContext(ctx, network, r.Server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if network == "udp" {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > dnsMaxBytes {
		return nil, ErrDNSLimit
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ParseResolvConf returns the first usable nameserver in resolv.conf format
// as host:port. Link-local addresses with zones are skipped.
func ParseResolvConf(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil || a.Zone() != "" {
			continue
		}
		return net.JoinHostPort(a.String(), "53"), nil
	}
	return "", errors.New("customdomain: no usable nameserver in resolv.conf")
}

// SystemResolver is the host's configured resolver, the default when
// server.custom_domains.dns_resolver is unset.
func SystemResolver() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	return ParseResolvConf(f)
}
