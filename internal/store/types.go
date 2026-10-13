package store

import "time"

// Tenant is an isolated identity domain with its own clients, users,
// connections and signing keys.
type Tenant struct {
	ID string
	// Name is unique and also serves as the subdomain under
	// server.base_domain.
	Name         string
	FriendlyName string
	// Domains are normalized hosts that resolve to this tenant.
	Domains []string
	// DefaultAudience is used when a token request has no audience.
	DefaultAudience string
	CreatedAt       time.Time
}
