// Package email sends zeroauthy's emails through a configurable driver:
// log (development), dir (writes .eml files; tests) or smtp.
package email

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroauthy/zeroauthy/internal/config"
)

// Message is one email. Text is required; HTML is optional.
type Message struct{ To, Subject, Text, HTML string }

type Mailer interface {
	Send(ctx context.Context, m Message) error
}

// ErrHeaderInjection is returned for a recipient or subject that is not a
// single plain address or contains line breaks.
var ErrHeaderInjection = errors.New("email: invalid recipient or subject")

// New builds the configured mailer. log may be nil.
func New(cfg config.Email, log *slog.Logger) (Mailer, error) {
	if log == nil {
		log = slog.Default()
	}
	switch cfg.Driver {
	case "", "log":
		return &logMailer{from: cfg.From, log: log}, nil
	case "dir":
		return &dirMailer{from: cfg.From, dir: cfg.Dir}, nil
	case "smtp":
		return &smtpMailer{from: cfg.From, cfg: cfg.SMTP}, nil
	}
	return nil, fmt.Errorf("email: unknown driver %q", cfg.Driver)
}
