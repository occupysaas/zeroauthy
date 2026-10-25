package protection

import (
	"context"
	"log/slog"
	"slices"
	"sync"
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

var notificationWarning struct {
	sync.Mutex
	next time.Time
}

func (s *Service) adminNotifications(ctx context.Context, tenant, feature string, shields []string) {
	if !slices.Contains(shields, "admin_notification") {
		return
	}
	notificationWarning.Lock()
	now := s.now()
	warn := !now.Before(notificationWarning.next)
	if warn {
		notificationWarning.next = now.Add(time.Hour)
	}
	notificationWarning.Unlock()
	if warn {
		log := s.Log
		if log == nil {
			log = slog.Default()
		}
		log.WarnContext(ctx, "protection admin notification deferred", "tenant", tenant, "feature", feature)
	}
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
