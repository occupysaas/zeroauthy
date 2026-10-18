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
	PasswordHistories    = store.PasswordHistories
	Users                = store.Users
	Sessions             = store.Sessions
	AuthTransactions     = store.AuthTransactions
	AuthCodes            = store.AuthCodes
	PushedAuthRequests   = store.PushedAuthRequests
	DeviceCodes          = store.DeviceCodes
	RefreshTokens        = store.RefreshTokens
	PasswordResetTickets = store.PasswordResetTickets
	Operators            = store.Operators

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
	ClientGrantFilter        = store.ClientGrantFilter
	Page                     = store.Page
	UserGrant                = store.UserGrant
	SubjectTypeAuthorization = store.SubjectTypeAuthorization
	KeyStatus                = store.KeyStatus
	SigningKey               = store.SigningKey
	PasswordOptions          = store.PasswordOptions
	PasswordComplexity       = store.PasswordComplexity
	PasswordHistory          = store.PasswordHistory
	PasswordDictionary       = store.PasswordDictionary
	PasswordProfileData      = store.PasswordProfileData
	ConnectionFilter         = store.ConnectionFilter
	Connection               = store.Connection
	Identity                 = store.Identity
	User                     = store.User
	LoginSession             = store.LoginSession
	AuthTransaction          = store.AuthTransaction
	AuthCode                 = store.AuthCode
	PushedAuthRequest        = store.PushedAuthRequest
	DeviceCode               = store.DeviceCode
	DeviceCodeStatus         = store.DeviceCodeStatus
	DeviceDecision           = store.DeviceDecision
	DevicePoll               = store.DevicePoll
	DevicePollOutcome        = store.DevicePollOutcome
	RefreshToken             = store.RefreshToken
	PasswordResetTicket      = store.PasswordResetTicket
	Operator                 = store.Operator
)

var (
	ErrNotFound    = store.ErrNotFound
	ErrConflict    = store.ErrConflict
	ErrAlreadyUsed = store.ErrAlreadyUsed

	ScriptNames      = store.ScriptNames
	CharacterTypes   = store.CharacterTypes
	LegacyComplexity = store.LegacyComplexity
)

const (
	DeviceCodePending  = store.DeviceCodePending
	DeviceCodeApproved = store.DeviceCodeApproved
	DeviceCodeDenied   = store.DeviceCodeDenied
	DeviceCodeConsumed = store.DeviceCodeConsumed

	PollPending  = store.PollPending
	PollSlowDown = store.PollSlowDown
	PollApproved = store.PollApproved
	PollDenied   = store.PollDenied
	PollExpired  = store.PollExpired
	PollInvalid  = store.PollInvalid

	MinPollGap = store.MinPollGap

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

	OperatorAllTenants = store.OperatorAllTenants

	OriginAPI = store.OriginAPI

	ScriptLogin          = store.ScriptLogin
	ScriptGetUser        = store.ScriptGetUser
	ScriptCreate         = store.ScriptCreate
	ScriptVerify         = store.ScriptVerify
	ScriptChangePassword = store.ScriptChangePassword
	ScriptDelete         = store.ScriptDelete
	ScriptChangeEmail    = store.ScriptChangeEmail

	RootAttributesOnEachLogin  = store.RootAttributesOnEachLogin
	RootAttributesOnFirstLogin = store.RootAttributesOnFirstLogin

	CharacterTypeUppercase = store.CharacterTypeUppercase
	CharacterTypeLowercase = store.CharacterTypeLowercase
	CharacterTypeNumber    = store.CharacterTypeNumber
	CharacterTypeSpecial   = store.CharacterTypeSpecial

	CharacterTypeRuleAll         = store.CharacterTypeRuleAll
	CharacterTypeRuleThreeOfFour = store.CharacterTypeRuleThreeOfFour

	PasswordAllow = store.PasswordAllow
	PasswordBlock = store.PasswordBlock

	MaxLengthError    = store.MaxLengthError
	MaxLengthTruncate = store.MaxLengthTruncate

	DictionaryEn10k  = store.DictionaryEn10k
	DictionaryEn100k = store.DictionaryEn100k
)
