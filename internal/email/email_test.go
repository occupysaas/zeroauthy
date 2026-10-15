package email

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/i18n"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

var msg = Message{To: "alice@example.test", Subject: "Réinitialiser", Text: "Open https://a.test/u/reset-password?ticket=abc=def", HTML: "<p>Open</p>"}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func TestBuildIsWellFormed(t *testing.T) {
	raw, err := build("zeroauthy@localhost", msg, time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"From: zeroauthy@localhost\r\n", "To: alice@example.test\r\n", "MIME-Version: 1.0\r\n",
		"Subject: =?utf-8?q?R=C3=A9initialiser?=\r\n", "multipart/alternative", "text/plain; charset=utf-8", "text/html; charset=utf-8",
		"Content-Transfer-Encoding: quoted-printable"} {
		if !strings.Contains(s, want) {
			t.Errorf("message lacks %q:\n%s", want, s)
		}
	}
}

func TestHeaderInjectionRejected(t *testing.T) {
	for _, bad := range []Message{
		{To: "a@x.test\r\nBcc: evil@x.test", Subject: "s", Text: "t"},
		{To: "a@x.test", Subject: "s\nBcc: evil@x.test", Text: "t"},
		{To: "not an address", Subject: "s", Text: "t"},
	} {
		if _, err := build("zeroauthy@localhost", bad, time.Now()); !errors.Is(err, ErrHeaderInjection) {
			t.Errorf("build(%q) err = %v, want ErrHeaderInjection", bad.To+"|"+bad.Subject, err)
		}
	}
}

func TestDirMailer(t *testing.T) {
	dir := t.TempDir()
	m, err := New(config.Email{Driver: "dir", Dir: dir, From: "zeroauthy@localhost"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.eml"))
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), "To: alice@example.test") {
		t.Fatalf("eml = %s", b)
	}
}

// fakeSMTP is a minimal SMTP server that does not offer STARTTLS.
func fakeSMTP(t *testing.T, got chan<- string, mailFrom ...chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r, w := bufio.NewReader(c), bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s + "\r\n"); w.Flush() }
		say("220 fake ESMTP")
		var data strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
				say("250-fake")
				say("250 8BITMIME")
			case strings.HasPrefix(cmd, "MAIL") && len(mailFrom) > 0:
				mailFrom[0] <- strings.TrimSpace(line)
				say("250 ok")
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"), strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					data.WriteString(l)
				}
				say("250 queued")
				got <- data.String()
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("502 no")
			}
		}
	}()
	return ln.Addr().String()
}

func TestSMTPInsecureSends(t *testing.T) {
	got := make(chan string, 1)
	host, port, _ := net.SplitHostPort(fakeSMTP(t, got))
	m, err := New(config.Email{Driver: "smtp", From: "zeroauthy@localhost",
		SMTP: config.SMTP{Host: host, Port: atoi(port), Insecure: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if body := <-got; !strings.Contains(body, "To: alice@example.test") {
		t.Fatalf("server received %q", body)
	}
}

func TestSMTPRequiresSTARTTLS(t *testing.T) {
	host, port, _ := net.SplitHostPort(fakeSMTP(t, make(chan string, 1)))
	m, _ := New(config.Email{Driver: "smtp", From: "zeroauthy@localhost", SMTP: config.SMTP{Host: host, Port: atoi(port)}}, nil)
	if err := m.Send(context.Background(), msg); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want STARTTLS required", err)
	}
}

func TestNewRejectsBadFrom(t *testing.T) {
	for _, from := range []string{"a@x.test\r\nBcc: e@x.test", "not an address"} {
		if _, err := New(config.Email{Driver: "log", From: from}, nil); err == nil {
			t.Errorf("New accepted From %q", from)
		}
	}
}

func TestSMTPDisplayNameFrom(t *testing.T) {
	got, mf := make(chan string, 1), make(chan string, 1)
	host, port, _ := net.SplitHostPort(fakeSMTP(t, got, mf))
	m, err := New(config.Email{Driver: "smtp", From: "Zéro Auth <z@x.test>",
		SMTP: config.SMTP{Host: host, Port: atoi(port), Insecure: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	if line := <-mf; !strings.HasPrefix(line, "MAIL FROM:<z@x.test>") {
		t.Errorf("envelope = %q, want bare address", line)
	}
	body := <-got
	if !strings.Contains(body, "From: =?utf-8?q?Z=C3=A9ro_Auth?= <z@x.test>") {
		t.Errorf("From header = %q", body)
	}
}

func TestBodyCRLFNotDoubled(t *testing.T) {
	raw, err := build("z@x.test", Message{To: "a@x.test", Subject: "s", Text: "a\r\nb\nc"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "\r\r") {
		t.Errorf("doubled CR in %q", raw)
	}
}

func TestResetPasswordMessage(t *testing.T) {
	tn := &store.Tenant{Name: "acme", FriendlyName: "Acme <b>Co</b>"}
	link := "https://acme.test/u/reset-password?ticket=abc"
	m := ResetPassword(i18n.New(tn, "en"), link)
	if m.Subject != "Reset your Acme <b>Co</b> password" {
		t.Errorf("subject = %q", m.Subject)
	}
	if !strings.Contains(m.Text, link) || !strings.Contains(m.Text, "Reset your password") {
		t.Errorf("text = %q", m.Text)
	}
	if !strings.Contains(m.HTML, `href="`+link+`"`) || !strings.Contains(m.HTML, `lang="en" dir="ltr"`) {
		t.Errorf("html = %q", m.HTML)
	}
	if strings.Contains(m.HTML, "<b>") || !strings.Contains(m.HTML, "&lt;b&gt;Co&lt;/b&gt;") {
		t.Errorf("hostile company name not escaped: %q", m.HTML)
	}
	if strings.Contains(m.Text, "&lt;") {
		t.Errorf("text part must not be HTML escaped: %q", m.Text)
	}
}

// logged sends msg through the log driver and returns the log output.
func logged(t *testing.T, cfg config.Email) string {
	t.Helper()
	var buf strings.Builder
	m, err := New(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Send(context.Background(), msg); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestLogDriverRedactsLinksByDefault(t *testing.T) {
	out := logged(t, config.Email{Driver: "log", From: "zeroauthy@localhost"})
	if strings.Contains(out, "abc") || !strings.Contains(out, "ticket=REDACTED") ||
		!strings.Contains(out, "alice@example.test") || !strings.Contains(out, "Réinitialiser") {
		t.Fatalf("log output = %s", out)
	}
}

func TestLogDriverShowsLinksWhenAsked(t *testing.T) {
	out := logged(t, config.Email{Driver: "log", From: "zeroauthy@localhost", LogLinks: true})
	if !strings.Contains(out, "ticket=abc=def") {
		t.Fatalf("log output = %s", out)
	}
}
