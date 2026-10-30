package grpcstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *Client) Logs() store.Logs { return store.UnimplementedLogs{} }

func (s *Client) LogsSupported(context.Context) error { return store.ErrLogsUnavailable }
