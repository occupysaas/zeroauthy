package i18n

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
	KeyErrLogoutInvalid       = "zeroauthy.error.logout-invalid"
)
