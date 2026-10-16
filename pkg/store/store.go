// Package store re-exports zeroauthy's storage interfaces and domain types
// for code outside this module, such as external storage plugins. The
// definitions and their documentation live in internal/store; every name
// here is an alias, so values are interchangeable.
package store

import "github.com/zeroauthy/zeroauthy/internal/store"

type (
	Store                = store.Store
	Tenants              = store.Tenants
	Clients              = store.Clients
	ResourceServers      = store.ResourceServers
	ClientGrants         = store.ClientGrants
	UserGrants           = store.UserGrants
	SigningKeys          = store.SigningKeys
	Connections          = store.Connections
	Users                = store.Users
	Sessions             = store.Sessions
	AuthTransactions     = store.AuthTransactions
	AuthCodes            = store.AuthCodes
	RefreshTokens        = store.RefreshTokens
	PasswordResetTickets = store.PasswordResetTickets

	Tenant                   = store.Tenant
	Branding                 = store.Branding
	CustomText               = store.CustomText
	AppType                  = store.AppType
	ClientSecret             = store.ClientSecret
	Client                   = store.Client
	RefreshTokenPolicy       = store.RefreshTokenPolicy
	Scope                    = store.Scope
	ResourceServer           = store.ResourceServer
	ClientGrant              = store.ClientGrant
	UserGrant                = store.UserGrant
	SubjectTypeAuthorization = store.SubjectTypeAuthorization
	KeyStatus                = store.KeyStatus
	SigningKey               = store.SigningKey
	PasswordPolicy           = store.PasswordPolicy
	Connection               = store.Connection
	Identity                 = store.Identity
	User                     = store.User
	LoginSession             = store.LoginSession
	AuthTransaction          = store.AuthTransaction
	AuthCode                 = store.AuthCode
	RefreshToken             = store.RefreshToken
	PasswordResetTicket      = store.PasswordResetTicket
)

var (
	ErrNotFound    = store.ErrNotFound
	ErrConflict    = store.ErrConflict
	ErrAlreadyUsed = store.ErrAlreadyUsed

	ScriptNames = store.ScriptNames
)

const (
	AppTypeSPA            = store.AppTypeSPA
	AppTypeRegularWeb     = store.AppTypeRegularWeb
	AppTypeNative         = store.AppTypeNative
	AppTypeNonInteractive = store.AppTypeNonInteractive

	AuthMethodNone              = store.AuthMethodNone
	AuthMethodClientSecretPost  = store.AuthMethodClientSecretPost
	AuthMethodClientSecretBasic = store.AuthMethodClientSecretBasic

	SecurityModeStrict     = store.SecurityModeStrict
	SecurityModePermissive = store.SecurityModePermissive

	RedirectionPolicyOpenRedirectProtection = store.RedirectionPolicyOpenRedirectProtection
	RedirectionPolicyAllowAlways            = store.RedirectionPolicyAllowAlways

	PolicyAllowAll           = store.PolicyAllowAll
	PolicyRequireClientGrant = store.PolicyRequireClientGrant
	PolicyDenyAll            = store.PolicyDenyAll

	SubjectTypeUser   = store.SubjectTypeUser
	SubjectTypeClient = store.SubjectTypeClient

	KeyNext     = store.KeyNext
	KeyCurrent  = store.KeyCurrent
	KeyPrevious = store.KeyPrevious
	KeyRevoked  = store.KeyRevoked

	StrategyDatabase = store.StrategyDatabase

	ScriptLogin          = store.ScriptLogin
	ScriptGetUser        = store.ScriptGetUser
	ScriptCreate         = store.ScriptCreate
	ScriptVerify         = store.ScriptVerify
	ScriptChangePassword = store.ScriptChangePassword
	ScriptDelete         = store.ScriptDelete
	ScriptChangeEmail    = store.ScriptChangeEmail

	RootAttributesOnEachLogin  = store.RootAttributesOnEachLogin
	RootAttributesOnFirstLogin = store.RootAttributesOnFirstLogin
)
