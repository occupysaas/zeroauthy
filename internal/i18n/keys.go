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
	KeyPasswordChangeRequired = "login.login.password-change-required"
	KeyEmailInUse             = "signup.signup.email-in-use"
	KeyInvalidUsername        = "signup.signup.invalid-username"
	KeyTooManyAttempts        = "zeroauthy.common.too-many-attempts"
	KeyPasswordTooLong        = "zeroauthy.signup.password-too-long"
	KeyPasswordTooShort       = "zeroauthy.signup.password-too-short"
	KeyPasswordClasses        = "zeroauthy.signup.password-character-classes"
	KeyPasswordTypes          = "zeroauthy.signup.password-character-types"
	KeyPasswordIdentical      = "zeroauthy.signup.password-identical-characters"
	KeyPasswordSequential     = "zeroauthy.signup.password-sequential-characters"
	KeyPasswordInHistory      = "zeroauthy.signup.password-in-history"
	KeyPasswordDictionary     = "zeroauthy.signup.password-in-dictionary"
	KeyPasswordPersonalInfo   = "zeroauthy.signup.password-personal-info"
	KeyUsernameTooShort       = "zeroauthy.signup.username-too-short"
	KeyUsernameTooLong        = "zeroauthy.signup.username-too-long"
	KeyErrSessionExpired      = "zeroauthy.error.session-expired"
	KeyErrNoConnection        = "zeroauthy.error.no-connection"
	KeyErrSignupDisabled      = "zeroauthy.error.signup-disabled"
	KeyErrServer              = "zeroauthy.error.server-error"
	KeyErrInvalidRequest      = "zeroauthy.error.invalid-request"
	KeyErrAccessDenied        = "zeroauthy.error.access-denied"
	KeyErrLogoutUnknownClient = "zeroauthy.error.logout-unknown-client"
	KeyErrLogoutURL           = "zeroauthy.error.logout-url-not-allowed"
	KeyEmailResetSubject      = "zeroauthy.email-reset-password.subject"
	KeyEmailVerifySubject     = "zeroauthy.email-verify-email.subject"
	// The user import completion email goes to operators, in English.
	KeyEmailImportDoneSubject   = "zeroauthy.email-import-done.subject"
	KeyEmailImportFailedSubject = "zeroauthy.email-import-done.subject-failed"
	KeyErrLogoutInvalid         = "zeroauthy.error.logout-invalid"
	KeyResetPasswordMismatch    = "reset-password.reset-password.password-mismatch"
	KeyResetNotChanged          = "zeroauthy.reset.not-changed"
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

// Email verification result screen keys (Auth0's email-verification
// prompt).
const (
	KeyVerifiedTitle              = "email-verification.email-verification-result.verifiedTitle"
	KeyVerifiedDescription        = "email-verification.email-verification-result.verifiedDescription"
	KeyVerifyErrorTitle           = "email-verification.email-verification-result.errorTitle"
	KeyVerifyErrorDescription     = "email-verification.email-verification-result.errorDescription"
	KeyAlreadyVerifiedDescription = "email-verification.email-verification-result.alreadyVerifiedDescription"
)

// Device code entry errors (Auth0's device-code-activation screen). One
// message covers an unknown, expired or used code (D7); invalid-code is in
// the catalog because Auth0 documents it, and is not shown.
const (
	KeyDeviceNoCode             = "device-flow.device-code-activation.no-code"
	KeyDeviceInvalidCode        = "device-flow.device-code-activation.invalid-code"
	KeyDeviceInvalidExpiredCode = "device-flow.device-code-activation.invalid-expired-code"
)
