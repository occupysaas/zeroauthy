package store

import (
	"context"
	"errors"
)

// ErrWSFedUnavailable reports a storage plugin without the wsfed.v1
// capability (Plan 37b): it cannot store client_aliases or form_template.
var ErrWSFedUnavailable = errors.New("store: wsfed.v1 unavailable")

// WSFedSupporter is implemented by stores that can tell whether they store
// Plan 37b's client fields.
type WSFedSupporter interface{ CheckWSFedSupport(context.Context) error }

// CheckWSFedSupport reports whether s stores Plan 37b's client fields.
// Stores that do not implement WSFedSupporter (memory, SQL) support them.
func CheckWSFedSupport(ctx context.Context, s Store) error {
	if capability, ok := s.(WSFedSupporter); ok {
		return capability.CheckWSFedSupport(ctx)
	}
	return nil
}

// ClientNeedsWSFed reports whether writing c needs wsfed.v1.
func ClientNeedsWSFed(c *Client) bool {
	return c != nil && (len(c.ClientAliases) > 0 || c.FormTemplate != "")
}
