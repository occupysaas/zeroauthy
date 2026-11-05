package grpcstore

import (
	"context"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// WebAuthn is not carried over the plugin protocol until Plan 33b Task 6.
func (c *Client) WebAuthn() store.WebAuthn { return store.UnimplementedWebAuthn{} }

// CheckWebAuthnSupport reports the missing capability until Task 6.
func (c *Client) CheckWebAuthnSupport(context.Context) error { return store.ErrWebAuthnUnavailable }

// WebAuthnSupported is false until Task 6.
func (c *Client) WebAuthnSupported() bool { return false }
