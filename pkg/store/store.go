// Package store re-exports zeroauthy's storage interfaces and domain types
// for code outside this module, such as external storage plugins. The
// definitions and their documentation live in internal/store; every name
// here is an alias, so values are interchangeable.
package store

import "github.com/zeroauthy/zeroauthy/internal/store"

type (
	RBAC                        = store.RBAC
	Actions                     = store.Actions
	UnimplementedActions        = store.UnimplementedActions
	ActionModule                = store.ActionModule
	ActionModuleVersion         = store.ActionModuleVersion
	ModuleRef                   = store.ModuleRef
	ModuleUser                  = store.ModuleUser
	ActionJob                   = store.ActionJob
	Action                      = store.Action
	ActionVersion               = store.ActionVersion
	ActionSecret                = store.ActionSecret
	ActionFilter                = store.ActionFilter
	Dependency                  = store.Dependency
	Build                       = store.Build
	BuildStatus                 = store.BuildStatus
	Binding                     = store.Binding
	BoundVersion                = store.BoundVersion
	Execution                   = store.Execution
	ExecutionResult             = store.ExecutionResult
	ContinueState               = store.ContinueState
	PageRequest                 = store.PageRequest
	Paged[T any]                = store.Paged[T]
	RBACSupporter               = store.RBACSupporter
	ActionsSupporter            = store.ActionsSupporter
	OrganizationsSupporter      = store.OrganizationsSupporter
	UnimplementedRBAC           = store.UnimplementedRBAC
	Organizations               = store.Organizations
	UnimplementedOrganizations  = store.UnimplementedOrganizations
	Organization                = store.Organization
	OrgBranding                 = store.OrgBranding
	OrgColors                   = store.OrgColors
	OrganizationConnection      = store.OrganizationConnection
	OrgPage                     = store.OrgPage
	OrgResult[T any]            = store.OrgResult[T]
	OrgLimits                   = store.OrgLimits
	Role                        = store.Role
	PermissionKey               = store.PermissionKey
	PermissionGrant             = store.PermissionGrant
	PermissionSource            = store.PermissionSource
	RBACPage                    = store.RBACPage
	RBACResult[T any]           = store.RBACResult[T]
	AuthorizationSnapshot       = store.AuthorizationSnapshot
	CustomDomains               = store.CustomDomains
	CustomDomain                = store.CustomDomain
	HostBinding                 = store.HostBinding
	TLSAssets                   = store.TLSAssets
	TLSAsset                    = store.TLSAsset
	TLSPublicData               = store.TLSPublicData
	TLSLease                    = store.TLSLease
	UnimplementedCustomDomains  = store.UnimplementedCustomDomains
	UnimplementedTLSAssets      = store.UnimplementedTLSAssets
	Protection                  = store.Protection
	ProtectionSettings          = store.ProtectionSettings
	BruteForcePolicy            = store.BruteForcePolicy
	SuspiciousIPPolicy          = store.SuspiciousIPPolicy
	SuspiciousIPStages          = store.SuspiciousIPStages
	ProtectionRate              = store.ProtectionRate
	BreachedPasswordPolicy      = store.BreachedPasswordPolicy
	BreachedPasswordStages      = store.BreachedPasswordStages
	ProtectionShields           = store.ProtectionShields
	BotPolicy                   = store.BotPolicy
	CAPTCHAPolicy               = store.CAPTCHAPolicy
	CAPTCHAProvider             = store.CAPTCHAProvider
	ArkoseProvider              = store.ArkoseProvider
	AuthChallengeProvider       = store.AuthChallengeProvider
	RecaptchaEnterpriseProvider = store.RecaptchaEnterpriseProvider
	ProtectionKey               = store.ProtectionKey
	ProtectionLimit             = store.ProtectionLimit
	ProtectionReceipt           = store.ProtectionReceipt
	ProtectionAdmission         = store.ProtectionAdmission
	ProtectionBlock             = store.ProtectionBlock
	ProtectionFilter            = store.ProtectionFilter
	UnimplementedProtection     = store.UnimplementedProtection

	HostedLoginConfig            = store.HostedLoginConfig
	HostedLoginState             = store.HostedLoginState
	HostedLogins                 = store.HostedLogins
	UnimplementedHostedLogins    = store.UnimplementedHostedLogins
	MicrosoftFederationSupporter = store.MicrosoftFederationSupporter
	Federation                   = store.Federation
	FederationAttempt            = store.FederationAttempt
	FederationEndpoints          = store.FederationEndpoints
	FederatedIdentityKey         = store.FederatedIdentityKey
	UnimplementedFederation      = store.UnimplementedFederation
	Store                        = store.Store
	Tenants                      = store.Tenants
	Clients                      = store.Clients
	ResourceServers              = store.ResourceServers
	ClientGrants                 = store.ClientGrants
	UserGrants                   = store.UserGrants
	SigningKeys                  = store.SigningKeys
	CustomSigningKeys            = store.CustomSigningKeys
	Connections                  = store.Connections
	PasswordHistories            = store.PasswordHistories
	Users                        = store.Users
	Sessions                     = store.Sessions
	AuthTransactions             = store.AuthTransactions
	AuthCodes                    = store.AuthCodes
	PushedAuthRequests           = store.PushedAuthRequests
	DeviceCodes                  = store.DeviceCodes
	RefreshTokens                = store.RefreshTokens
	PasswordResetTickets         = store.PasswordResetTickets
	EmailVerificationTickets     = store.EmailVerificationTickets
	Operators                    = store.Operators
	Jobs                         = store.Jobs
	EmailProviders               = store.EmailProviders
	EmailTemplates               = store.EmailTemplates
	EmailNotifications           = store.EmailNotifications

	Tenant                          = store.Tenant
	Branding                        = store.Branding
	CustomText                      = store.CustomText
	AppType                         = store.AppType
	ClientSecret                    = store.ClientSecret
	Client                          = store.Client
	RefreshTokenPolicy              = store.RefreshTokenPolicy
	Scope                           = store.Scope
	ResourceServer                  = store.ResourceServer
	ClientGrant                     = store.ClientGrant
	ClientGrantFilter               = store.ClientGrantFilter
	Page                            = store.Page
	UserGrant                       = store.UserGrant
	SubjectTypeAuthorization        = store.SubjectTypeAuthorization
	KeyStatus                       = store.KeyStatus
	SigningKey                      = store.SigningKey
	SigningKeyRotation              = store.SigningKeyRotation
	CustomSigningKeySet             = store.CustomSigningKeySet
	PasswordOptions                 = store.PasswordOptions
	PasswordComplexity              = store.PasswordComplexity
	PasswordHistory                 = store.PasswordHistory
	PasswordDictionary              = store.PasswordDictionary
	PasswordProfileData             = store.PasswordProfileData
	ConnectionFilter                = store.ConnectionFilter
	Connection                      = store.Connection
	Identity                        = store.Identity
	User                            = store.User
	LoginSession                    = store.LoginSession
	AuthTransaction                 = store.AuthTransaction
	AuthCode                        = store.AuthCode
	PushedAuthRequest               = store.PushedAuthRequest
	DeviceCode                      = store.DeviceCode
	DeviceCodeStatus                = store.DeviceCodeStatus
	DeviceDecision                  = store.DeviceDecision
	DevicePoll                      = store.DevicePoll
	DevicePollOutcome               = store.DevicePollOutcome
	RefreshToken                    = store.RefreshToken
	PasswordResetTicket             = store.PasswordResetTicket
	EmailVerificationTicket         = store.EmailVerificationTicket
	UserGrantFilter                 = store.UserGrantFilter
	ClientFilter                    = store.ClientFilter
	Operator                        = store.Operator
	JobType                         = store.JobType
	JobStatus                       = store.JobStatus
	JobSummary                      = store.JobSummary
	Job                             = store.Job
	JobErrorItem                    = store.JobErrorItem
	JobError                        = store.JobError
	EmailProvider                   = store.EmailProvider
	EmailTemplate                   = store.EmailTemplate
	EmailNotification               = store.EmailNotification
	UnimplementedEmailProviders     = store.UnimplementedEmailProviders
	UnimplementedEmailTemplates     = store.UnimplementedEmailTemplates
	UnimplementedEmailNotifications = store.UnimplementedEmailNotifications
)

var (
	ErrCustomDomainRepositoryUnavailable = store.ErrCustomDomainRepositoryUnavailable
	ErrTLSAssetRepositoryUnavailable     = store.ErrTLSAssetRepositoryUnavailable
	ErrNotFound                          = store.ErrNotFound
	ErrConflict                          = store.ErrConflict
	ErrAlreadyUsed                       = store.ErrAlreadyUsed
	ErrPrecondition                      = store.ErrPrecondition
	ErrInvalid                           = store.ErrInvalid
	ErrEmailRepositoryUnavailable        = store.ErrEmailRepositoryUnavailable
	ErrFederationUnavailable             = store.ErrFederationUnavailable

	ScriptNames      = store.ScriptNames
	CharacterTypes   = store.CharacterTypes
	LegacyComplexity = store.LegacyComplexity
)

const (
	HostCanonical       = store.HostCanonical
	HostOperator        = store.HostOperator
	HostPublic          = store.HostPublic
	HostOrigin          = store.HostOrigin
	TLSAssetAccount     = store.TLSAssetAccount
	TLSAssetOrder       = store.TLSAssetOrder
	TLSAssetCertificate = store.TLSAssetCertificate
	TLSAssetChallenge   = store.TLSAssetChallenge
	TLSAssetDNSIntent   = store.TLSAssetDNSIntent
	AttemptPending      = store.AttemptPending
	AttemptClaimed      = store.AttemptClaimed
	AttemptFinished     = store.AttemptFinished
	DeviceCodePending   = store.DeviceCodePending
	DeviceCodeApproved  = store.DeviceCodeApproved
	DeviceCodeDenied    = store.DeviceCodeDenied
	DeviceCodeConsumed  = store.DeviceCodeConsumed

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

	JobUsersImport       = store.JobUsersImport
	JobUsersExport       = store.JobUsersExport
	JobVerificationEmail = store.JobVerificationEmail
	JobPending           = store.JobPending
	JobProcessing        = store.JobProcessing
	JobCompleted         = store.JobCompleted
	JobFailed            = store.JobFailed
	JobMaxAttempts       = store.JobMaxAttempts
	JobMaxChunk          = store.JobMaxChunk
	JobMaxRuntime        = store.JobMaxRuntime
	JobDetailTimedOut    = store.JobDetailTimedOut
	JobDetailWorkerLost  = store.JobDetailWorkerLost

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

var ErrProtectionUnimplemented = store.ErrProtectionUnimplemented
var CloneSettings = store.CloneSettings

// ValidateProtectionSecrets rejects accidental plaintext CAPTCHA persistence.
var ValidateProtectionSecrets = store.ValidateProtectionSecrets

const (
	ProtectionBruteForce               = store.ProtectionBruteForce
	ProtectionSuspiciousIPLogin        = store.ProtectionSuspiciousIPLogin
	ProtectionSuspiciousIPRegistration = store.ProtectionSuspiciousIPRegistration
	ProtectionResetMail                = store.ProtectionResetMail
)

var ErrRBACUnavailable = store.ErrRBACUnavailable
var ErrOrganizationsUnavailable = store.ErrOrganizationsUnavailable
var ErrActionsUnavailable = store.ErrActionsUnavailable
var ErrBuildNotReady = store.ErrBuildNotReady
