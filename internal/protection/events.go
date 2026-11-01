package protection

import (
	"context"
	"log/slog"
	"time"
)

// Only stable actor IDs belong here, never credentials, tokens or raw aliases.
func (s *Service) Event(ctx context.Context, tenant, feature, outcome, actorID string) {
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	log.InfoContext(ctx, "security protection", "tenant", tenant, "feature", feature, "outcome", outcome, "actor_id", actorID)
}

func (s *Service) notify(ctx context.Context, tenant, user, purpose string) {
	if s.Notifier == nil {
		return
	}
	goSend := s.Go
	if goSend == nil {
		goSend = func(f func()) { go f() }
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	goSend(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.Notifier.Notify(ctx, tenant, user, purpose); err != nil {
			// Do not include provider errors or user supplied identifiers in logs.
			log.WarnContext(ctx, "protection user notification failed", "tenant", tenant, "purpose", purpose)
		}
	})
}
