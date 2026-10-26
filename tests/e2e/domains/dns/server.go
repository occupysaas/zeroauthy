// Package dns is a local authoritative DNS answerer for Plan 23 tests,
// built on golang.org/x/net/dns/dnsmessage (BSD-3-Clause). It answers A with
// a fixed address, TXT and NS/CNAME from callbacks, and never recurses.
package dns

import (
	"net"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

// Server answers queries on a UDP socket until Close.
type Server struct {
	A     [4]byte
	TXT   func(name string) []string // fully qualified, lower case, no dot
	CNAME func(name string) string   // "" when none
	NS    func(name string) []string

	pc   net.PacketConn
	once sync.Once
	mu   sync.Mutex
}

// Set changes the callbacks while the server runs.
func (s *Server) Set(fn func(*Server)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// Listen starts answering on addr (e.g. 127.0.0.1:8053, or :0).
func (s *Server) Listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	s.pc = pc
	go s.loop()
	return nil
}

func (s *Server) Addr() string { return s.pc.LocalAddr().String() }

func (s *Server) Close() { s.once.Do(func() { s.pc.Close() }) }

func (s *Server) loop() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
			continue
		}
		s.mu.Lock()
		resp := s.answer(q)
		s.mu.Unlock()
		if out, err := resp.Pack(); err == nil {
			_, _ = s.pc.WriteTo(out, addr)
		}
	}
}

func (s *Server) answer(q dnsmessage.Message) dnsmessage.Message {
	qq := q.Questions[0]
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, Authoritative: true}, Questions: q.Questions}
	name := strings.TrimSuffix(strings.ToLower(qq.Name.String()), ".")
	hdr := func(t dnsmessage.Type) dnsmessage.ResourceHeader {
		return dnsmessage.ResourceHeader{Name: qq.Name, Type: t, Class: dnsmessage.ClassINET, TTL: 1}
	}
	if s.CNAME != nil {
		if target := s.CNAME(name); target != "" {
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(dnsmessage.TypeCNAME), Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")}})
			return resp
		}
	}
	switch qq.Type {
	case dnsmessage.TypeA:
		resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(dnsmessage.TypeA), Body: &dnsmessage.AResource{A: s.A}})
	case dnsmessage.TypeTXT:
		if s.TXT != nil {
			for _, v := range s.TXT(name) {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(dnsmessage.TypeTXT), Body: &dnsmessage.TXTResource{TXT: []string{v}}})
			}
		}
	case dnsmessage.TypeNS:
		if s.NS != nil {
			for _, v := range s.NS(name) {
				resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr(dnsmessage.TypeNS), Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName(v + ".")}})
			}
		}
	}
	return resp
}
