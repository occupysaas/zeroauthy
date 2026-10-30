package email

import (
	"context"
	"log/slog"
	"regexp"
	"time"
)

// ticketValue matches a reset ticket in a link.
var ticketValue = regexp.MustCompile(`ticket=[^&\s"]+`)

// logMailer writes each message to the log instead of sending it. It is for
// development only. Reset tickets are replaced by REDACTED unless showLinks
// is set (email.log_links), because a logged link is a working credential.
type logMailer struct {
	from      string
	log       *slog.Logger
	showLinks bool
}

func (l *logMailer) Send(ctx context.Context, m Message) error {
	if _, err := build(l.from, m, time.Now()); err != nil {
		return err
	}
	if m.Type == "user_invitation" {
		l.log.InfoContext(ctx, "email (log driver)", "type", m.Type)
		return nil
	}
	text := m.Text
	if !l.showLinks {
		text = ticketValue.ReplaceAllString(text, "ticket=REDACTED")
	}
	l.log.InfoContext(ctx, "email (log driver)", "to", m.To, "subject", m.Subject, "text", text)
	return nil
}
