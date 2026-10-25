package sqlstore

import "github.com/zeroauthy/zeroauthy/internal/store"

// These closed adapters keep older SQL schemas fail-closed until Task 4
// replaces them with the durable implementations.
func (s *Store) EmailProviders() store.EmailProviders { return store.UnimplementedEmailProviders{} }
func (s *Store) EmailTemplates() store.EmailTemplates { return store.UnimplementedEmailTemplates{} }
func (s *Store) EmailNotifications() store.EmailNotifications {
	return store.UnimplementedEmailNotifications{}
}
