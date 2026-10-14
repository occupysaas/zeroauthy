package email

import (
	"context"
	"log/slog"
	"time"
)

// logMailer writes each message to the log instead of sending it. It is for
// development only: reset links and tickets appear in the log output.
type logMailer struct {
	from string
	log  *slog.Logger
}

func (l *logMailer) Send(ctx context.Context, m Message) error {
	if _, err := build(l.from, m, time.Now()); err != nil {
		return err
	}
	l.log.InfoContext(ctx, "email (log driver)", "to", m.To, "subject", m.Subject, "text", m.Text)
	return nil
}
