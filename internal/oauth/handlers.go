// internal/oauth/handlers.go

// Package oauth implements the OAuth 2.0 endpoints of the Authentication
// API.
package oauth

import (
	"log/slog"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

type Handlers struct {
	Protection *protection.Service
	Store      store.Store
	Log        *slog.Logger
	Now        func() time.Time

	// BaseDomain is server.base_domain; it names each tenant's Management
	// API identifier (tenant.ManagementAPIIdentifier).
	BaseDomain string

	Minter *Minter

	// Wrapper opens sealed client secrets (D-0038). Nil makes every
	// sealed secret fail to authenticate; legacy hashes still work.
	Wrapper keys.Wrapper

	// Database and Protection serve the password grants.
	// The throttles are the hosted login's, so both paths share limits.
	Database          *identity.Database
	TrustProxyHeaders bool

	// Actions runs post-login and credentials-exchange flows; nil runs
	// none. Sealed effects on codes and device approvals open with Wrapper.
	Actions *actions.Engine
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handlers) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Handlers) protectionService() *protection.Service {
	if h.Protection != nil {
		return h.Protection
	}
	return &protection.Service{Store: h.Store, Now: h.Now, Log: h.Log}
}
