package sqlstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (s *Store) Logs() store.Logs { return store.UnimplementedLogs{} }

func (s *Store) LogsSupported(context.Context) error { return store.ErrLogsUnavailable }
