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

func (s *Service) notifications(ctx context.Context, tenant, feature string, shields []string) {
	if !slices.Contains(shields, "user_notification") && !slices.Contains(shields, "admin_notification") {
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
		log.WarnContext(ctx, "protection notifications deferred", "tenant", tenant, "feature", feature)
	}
}
