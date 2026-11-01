package sqlstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *Store) Events() store.Events                     { return store.UnimplementedEvents{} }
func (s *Store) CheckEventsSupport(context.Context) error { return store.ErrEventsUnavailable }
func (s *Store) EventsSupported() bool                    { return false }
