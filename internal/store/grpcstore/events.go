package grpcstore

import (
	"context"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *Client) Events() store.Events                     { return store.UnimplementedEvents{} }
func (s *Client) CheckEventsSupport(context.Context) error { return store.ErrEventsUnavailable }
func (s *Client) EventsSupported() bool                    { return false }
