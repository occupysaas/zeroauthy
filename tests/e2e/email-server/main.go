package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

type sink struct {
	mu       sync.Mutex
	messages []string
}

func (s *sink) add(v string) { s.mu.Lock(); s.messages = append(s.messages, v); s.mu.Unlock() }
func (s *sink) list(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("content-type", "application/json")
	messages := append([]string{}, s.messages...)
	_ = json.NewEncoder(w).Encode(messages)
}
func (s *sink) clear(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.messages = []string{}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	cert, err := tls.LoadX509KeyPair(os.Getenv("E2E_SMTP_CERT"), os.Getenv("E2E_SMTP_KEY"))
	if err != nil {
		panic(err)
	}
	addr := env("E2E_SMTP_ADDR", "127.0.0.1:2526")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	s := &sink{}
	http.HandleFunc("/messages", s.list)
	http.HandleFunc("/clear", s.clear)
	go func() { _ = http.ListenAndServe(env("E2E_SMTP_HTTP_ADDR", "127.0.0.1:2527"), nil) }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go smtpSession(conn, cert, s)
	}
}

func smtpSession(conn net.Conn, cert tls.Certificate, s *sink) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	write := func(v string) { _, _ = io.WriteString(writer, v+"\r\n"); _ = writer.Flush() }
	write("220 local email sink")
	data := false
	var message strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if data {
			if line == "." {
				data = false
				s.add(message.String())
				message.Reset()
				write("250 accepted")
				continue
			}
			if strings.HasPrefix(line, "..") {
				line = line[1:]
			}
			message.WriteString(line + "\r\n")
			continue
		}
		switch {
		case strings.HasPrefix(strings.ToUpper(line), "EHLO "):
			write("250-localhost")
			write("250-STARTTLS")
			write("250 SIZE 10485760")
		case strings.EqualFold(line, "STARTTLS"):
			write("220 ready for TLS")
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			reader = bufio.NewReader(conn)
			writer = bufio.NewWriter(conn)
		case strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:"):
			write("250 sender ok")
		case strings.HasPrefix(strings.ToUpper(line), "RCPT TO:"):
			write("250 recipient ok")
		case strings.EqualFold(line, "DATA"):
			data = true
			write("354 end with dot")
		case strings.EqualFold(line, "RSET"):
			message.Reset()
			write("250 reset")
		case strings.EqualFold(line, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 ok")
		}
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
