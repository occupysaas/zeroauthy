package i18n

// KeyPasswordPolicyAlias is Auth0's signup key for a password that fails the
// policy. It is not in en.json and has no built-in text: when a tenant sets
// it for the language, it replaces all three password policy messages
// (too short, too long, character classes). The catalog test exempts it.
const KeyPasswordPolicyAlias = "signup.signup.password-policy-not-conformant"

// Keys used from Go code. The catalog test checks each exists in en.json.
const (
	KeyWrongCredentials       = "login.login.wrong-credentials"
	KeyUserBlocked            = "login.login.user-blocked"
	KeyEmailInUse             = "signup.signup.email-in-use"
	KeyInvalidUsername        = "signup.signup.invalid-username"
	KeyTooManyAttempts        = "zeroauthy.common.too-many-attempts"
	KeyPasswordTooLong        = "zeroauthy.signup.password-too-long"
	KeyPasswordTooShort       = "zeroauthy.signup.password-too-short"
	KeyPasswordClasses        = "zeroauthy.signup.password-character-classes"
	KeyErrSessionExpired      = "zeroauthy.error.session-expired"
	KeyErrNoConnection        = "zeroauthy.error.no-connection"
	KeyErrSignupDisabled      = "zeroauthy.error.signup-disabled"
	KeyErrServer              = "zeroauthy.error.server-error"
	KeyErrInvalidRequest      = "zeroauthy.error.invalid-request"
	KeyErrLogoutUnknownClient = "zeroauthy.error.logout-unknown-client"
	KeyErrLogoutURL           = "zeroauthy.error.logout-url-not-allowed"
	KeyEmailResetSubject      = "zeroauthy.email-reset-password.subject"
	KeyErrLogoutInvalid       = "zeroauthy.error.logout-invalid"
	KeyResetPasswordMismatch  = "reset-password.reset-password.password-mismatch"
)

// Password reset error screen keys (Auth0's reset-password-error screen).
const (
	KeyResetErrExpiredTitle = "reset-password.reset-password-error.eventTitleExpired"
	KeyResetErrExpired      = "reset-password.reset-password-error.descriptionExpired"
	KeyResetErrUsedTitle    = "reset-password.reset-password-error.eventTitleUsed"
	KeyResetErrUsed         = "reset-password.reset-password-error.descriptionUsed"
	KeyResetErrGenericTitle = "reset-password.reset-password-error.eventTitleGeneric"
	KeyResetErrGeneric      = "reset-password.reset-password-error.descriptionGeneric"
)
