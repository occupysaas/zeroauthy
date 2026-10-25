package providers

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

type smtpTransport struct {
	f          *Factory
	host       string
	port       int
	user, pass string
}

func (t *smtpTransport) Send(ctx context.Context, m Message) error {
	if err := validMessage(m); err != nil {
		return err
	}
	addr := net.JoinHostPort(t.host, strconv.Itoa(t.port))
	var conn net.Conn
	var err error
	if t.f != nil && t.f.DialContext != nil {
		conn, err = t.f.DialContext(ctx, "tcp", addr)
	} else {
		allow := []string(nil)
		if t.f != nil {
			allow = t.f.LocalSMTPAllowlist
		}
		conn, err = newPolicyDialer(allow).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return errors.New("email provider: SMTP connection failed")
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	defer conn.Close()
	deadline := time.Now().Add(sendTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, t.host)
	if err != nil {
		return errors.New("email provider: SMTP handshake failed")
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err = c.StartTLS(&tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12}); err != nil {
			return errors.New("email provider: SMTP TLS negotiation failed")
		}
	} else {
		return errors.New("email provider: SMTP server does not offer STARTTLS")
	}
	if t.user != "" {
		if err = c.Auth(smtp.PlainAuth("", t.user, t.pass, t.host)); err != nil {
			return errors.New("email provider: SMTP authentication failed")
		}
	}
	from, err := mail.ParseAddress(m.From)
	if err != nil {
		return errors.New("email provider: invalid sender")
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return errors.New("email provider: invalid recipient")
	}
	if err = c.Mail(from.Address); err != nil {
		return errors.New("email provider: SMTP sender rejected")
	}
	if err = c.Rcpt(to.Address); err != nil {
		return errors.New("email provider: SMTP recipient rejected")
	}
	w, err := c.Data()
	if err != nil {
		return errors.New("email provider: SMTP message rejected")
	}
	content := buildMIME(m)
	if _, err = w.Write([]byte(content)); err != nil {
		return errors.New("email provider: SMTP message write failed")
	}
	if err = w.Close(); err != nil {
		return errors.New("email provider: SMTP message acceptance uncertain")
	}
	if err = c.Quit(); err != nil {
		return fmt.Errorf("email provider: SMTP message accepted; session close failed")
	}
	return nil
}
func buildMIME(m Message) string {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	boundary := mw.Boundary()
	var out strings.Builder
	out.WriteString("From: " + m.From + "\r\nTo: " + m.To + "\r\nSubject: " + strings.ReplaceAll(m.Subject, "\r", "") + "\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")
	for _, part := range []struct{ typ, text string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		header := textproto.MIMEHeader{}
		header.Set("Content-Type", part.typ+"; charset=utf-8")
		header.Set("Content-Transfer-Encoding", "8bit")
		w, err := mw.CreatePart(header)
		if err == nil {
			_, _ = w.Write([]byte(part.text))
		}
	}
	_ = mw.Close()
	out.Write(body.Bytes())
	return out.String()
}
