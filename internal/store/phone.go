package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

var ErrPhoneUnavailable = errors.New("store: phone unavailable")

type PhoneProvider struct {
	TenantID, ID, Name   string // Name: twilio|custom|sns
	Disabled             bool
	Configuration        json.RawMessage // public: sid, default_from, mssid, delivery_methods, region, sender_id, sms_type
	SealedCredentials    []byte          // auth_token / SNS access key + secret
	CreatedAt, UpdatedAt time.Time
}
type PhoneTemplate struct {
	TenantID, ID, Type   string // Type per phonerules (otp_verify, otp_enroll, change_password, blocked_account, password_breach)
	Disabled             bool
	Content              json.RawMessage // from, body.text, body.voice, syntax
	Customizable         bool
	CreatedAt, UpdatedAt time.Time
}
type PasswordlessCode struct {
	TenantID, ConnectionID, Identifier string // Identifier: lowercased email or E.164
	ClientID, Kind                     string // Kind: code|link
	CodeHash                           string
	Request                            json.RawMessage // sealed authParams for links
	Attempts                           int
	ExpiresAt, CreatedAt               time.Time
}

type Phone interface {
	ListPhoneProviders(ctx context.Context, tid string) ([]PhoneProvider, error)
	GetPhoneProvider(ctx context.Context, tid, id string) (*PhoneProvider, error)
	CreatePhoneProvider(ctx context.Context, p *PhoneProvider) error // ErrConflict if tenant already has one (Auth0: one provider); ErrNotFound if tenant missing
	UpdatePhoneProvider(ctx context.Context, p *PhoneProvider) error // ErrNotFound if missing
	DeletePhoneProvider(ctx context.Context, tid, id string) error   // ErrNotFound if missing

	ListPhoneTemplates(ctx context.Context, tid string) ([]PhoneTemplate, error) // defaults merged by caller
	GetPhoneTemplate(ctx context.Context, tid, id string) (*PhoneTemplate, error)
	PutPhoneTemplate(ctx context.Context, t *PhoneTemplate) error // upsert by ID; ErrConflict if another template of the tenant has the same Type
	DeletePhoneTemplate(ctx context.Context, tid, id string) error

	PutPasswordlessCode(ctx context.Context, c *PasswordlessCode) error // replaces any row for (tid, connection, identifier, kind); ErrNotFound if tenant missing
	// FailPasswordlessCode atomically increments attempts. ErrNotFound if no row.
	FailPasswordlessCode(ctx context.Context, tid, conn, ident, kind string, now time.Time) (attempts int, err error)
	// ConsumePasswordlessCode atomically deletes and returns the row. ErrPrecondition
	// unless the row exists, the hash matches, it is unexpired at now and attempts < maxAttempts.
	ConsumePasswordlessCode(ctx context.Context, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*PasswordlessCode, error)
	// PeekPasswordlessLink returns an unexpired link row by code hash without
	// consuming it. ErrNotFound if missing or expired.
	PeekPasswordlessLink(ctx context.Context, tid, hash string, now time.Time) (*PasswordlessCode, error)

	// FindUsersByPhone matches User.PhoneNormalized within the tenant and a
	// user identity on the connection. An empty e164 matches nothing.
	FindUsersByPhone(ctx context.Context, tid, connection, e164 string) ([]User, error)
	PurgePhone(ctx context.Context, before time.Time, limit int) (int, error) // expired passwordless codes
	DeleteTenantPhone(ctx context.Context, tid string) error
}

type UnimplementedPhone struct{}

func (UnimplementedPhone) ListPhoneProviders(ctx context.Context, tid string) ([]PhoneProvider, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) GetPhoneProvider(ctx context.Context, tid, id string) (*PhoneProvider, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) CreatePhoneProvider(ctx context.Context, p *PhoneProvider) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) UpdatePhoneProvider(ctx context.Context, p *PhoneProvider) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) DeletePhoneProvider(ctx context.Context, tid, id string) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) ListPhoneTemplates(ctx context.Context, tid string) ([]PhoneTemplate, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) GetPhoneTemplate(ctx context.Context, tid, id string) (*PhoneTemplate, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) PutPhoneTemplate(ctx context.Context, t *PhoneTemplate) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) DeletePhoneTemplate(ctx context.Context, tid, id string) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) PutPasswordlessCode(ctx context.Context, c *PasswordlessCode) error {
	return ErrPhoneUnavailable
}
func (UnimplementedPhone) FailPasswordlessCode(ctx context.Context, tid, conn, ident, kind string, now time.Time) (int, error) {
	return 0, ErrPhoneUnavailable
}
func (UnimplementedPhone) ConsumePasswordlessCode(ctx context.Context, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*PasswordlessCode, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) PeekPasswordlessLink(ctx context.Context, tid, hash string, now time.Time) (*PasswordlessCode, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) FindUsersByPhone(ctx context.Context, tid, connection, e164 string) ([]User, error) {
	return nil, ErrPhoneUnavailable
}
func (UnimplementedPhone) PurgePhone(ctx context.Context, before time.Time, limit int) (int, error) {
	return 0, ErrPhoneUnavailable
}
func (UnimplementedPhone) DeleteTenantPhone(ctx context.Context, tid string) error {
	return ErrPhoneUnavailable
}
