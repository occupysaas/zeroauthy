package store

import (
	"context"
	"errors"
	"time"
)

var ErrEmailRepositoryUnavailable = errors.New("store: email repositories unavailable; upgrade the storage plugin")

type EmailProvider struct {
	TenantID          string
	Name              string
	Enabled           bool
	DefaultFrom       string
	PublicConfig      map[string]any
	SealedCredentials []byte
	Revision          int64
}

type EmailTemplate struct {
	TenantID string
	Name     string
	Fields   map[string]any
	Revision int64
}

type EmailNotification struct {
	TenantID, SubjectID, Purpose, EventKey string
	Count                                  int
	ExpiresAt                              time.Time
}

type EmailProviders interface {
	Get(context.Context, string) (*EmailProvider, error)
	Put(context.Context, *EmailProvider, int64) error
	Delete(context.Context, string, int64) error
}

type EmailTemplates interface {
	Get(context.Context, string, string) (*EmailTemplate, error)
	Put(context.Context, *EmailTemplate, int64) error
}

type EmailNotifications interface {
	Claim(context.Context, string, string, string, string, time.Time, time.Time, int) (bool, error)
	Sweep(context.Context, time.Time, int) (int, error)
}

type UnimplementedEmailProviders struct{}

func (UnimplementedEmailProviders) Get(context.Context, string) (*EmailProvider, error) {
	return nil, ErrEmailRepositoryUnavailable
}
func (UnimplementedEmailProviders) Put(context.Context, *EmailProvider, int64) error {
	return ErrEmailRepositoryUnavailable
}
func (UnimplementedEmailProviders) Delete(context.Context, string, int64) error {
	return ErrEmailRepositoryUnavailable
}

type UnimplementedEmailTemplates struct{}

func (UnimplementedEmailTemplates) Get(context.Context, string, string) (*EmailTemplate, error) {
	return nil, ErrEmailRepositoryUnavailable
}
func (UnimplementedEmailTemplates) Put(context.Context, *EmailTemplate, int64) error {
	return ErrEmailRepositoryUnavailable
}

type UnimplementedEmailNotifications struct{}

func (UnimplementedEmailNotifications) Claim(context.Context, string, string, string, string, time.Time, time.Time, int) (bool, error) {
	return false, ErrEmailRepositoryUnavailable
}
func (UnimplementedEmailNotifications) Sweep(context.Context, time.Time, int) (int, error) {
	return 0, ErrEmailRepositoryUnavailable
}
