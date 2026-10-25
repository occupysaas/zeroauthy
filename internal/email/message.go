package email

import (
	"bytes"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
)

// build renders m as an RFC 5322 message with a multipart/alternative body.
func build(from string, m Message, now time.Time) ([]byte, error) {
	if m.From != "" {
		from = m.From
	}
	if err := validateMessage(from, m); err != nil {
		return nil, ErrHeaderInjection
	}
	addr, _ := mail.ParseAddress(from)
	if addr.Name != "" {
		from = addr.String()
	} else {
		from = addr.Address
	}
	boundary := "za-" + secrets.RandomString(24)
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@zeroauthy>\r\nMIME-Version: 1.0\r\n",
		from, m.To, mime.QEncoding.Encode("utf-8", m.Subject), now.UTC().Format(time.RFC1123Z), secrets.RandomString(24))
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
	part := func(ctype, body string) {
		fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		w := quotedprintable.NewWriter(&b)
		_, _ = w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
		_ = w.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", m.Text)
	if m.HTML != "" {
		part("text/html", m.HTML)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}
