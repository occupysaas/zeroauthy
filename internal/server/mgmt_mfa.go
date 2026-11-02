package server

import (
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
	"github.com/zeroauthy/zeroauthy/internal/mgmt"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
	"github.com/zeroauthy/zeroauthy/internal/tenantsetup"
	"net/http"
	"slices"
)

func (a mgmtAPI) CreateGuardianEnrollmentTicket(w http.ResponseWriter, r *http.Request, params mgmtapi.CreateGuardianEnrollmentTicketParams) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "CreateGuardianEnrollmentTicket", "", "")
	}, "create:guardian_enrollment_tickets")
}
func (a mgmtAPI) GetGuardianEnrollment(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "GetGuardianEnrollment", id, "") }, "read:guardian_enrollments")
}
func (a mgmtAPI) DeleteGuardianEnrollment(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "DeleteGuardianEnrollment", id, "")
	}, "delete:guardian_enrollments")
}
func (a mgmtAPI) GetGuardianFactors(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "GetGuardianFactors", "", "") }, "read:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsDuoSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsDuoSettings", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) UpdateGuardianFactorsDuoSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateGuardianFactorsDuoSettings", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsDuoSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsDuoSettings", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsEmailSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsEmailSettings", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsEmailSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsEmailSettings", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPhoneMessageTypes(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPhoneMessageTypes", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPhoneMessageTypes(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPhoneMessageTypes", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPhoneProvidersTwilio(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPhoneProvidersTwilio", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPhoneProvidersTwilio(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPhoneProvidersTwilio", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPhoneSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPhoneSelectedProvider", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPhoneSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPhoneSelectedProvider", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPhoneSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPhoneSettings", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPhoneSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPhoneSettings", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPhoneTemplates(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPhoneTemplates", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPhoneTemplates(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPhoneTemplates", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPushNotificationProvidersApns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPushNotificationProvidersApns", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) UpdateGuardianFactorsPushNotificationProvidersApns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateGuardianFactorsPushNotificationProvidersApns", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPushNotificationProvidersApns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPushNotificationProvidersApns", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) UpdateGuardianFactorsPushNotificationProvidersFcm(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateGuardianFactorsPushNotificationProvidersFcm", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPushNotificationProvidersFcm(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPushNotificationProvidersFcm", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) UpdateGuardianFactorsPushNotificationProvidersFcmv1(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateGuardianFactorsPushNotificationProvidersFcmv1", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPushNotificationProvidersFcmv1(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPushNotificationProvidersFcmv1", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPushNotificationProvidersSns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPushNotificationProvidersSns", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) UpdateGuardianFactorsPushNotificationProvidersSns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateGuardianFactorsPushNotificationProvidersSns", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPushNotificationProvidersSns(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPushNotificationProvidersSns", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsPushNotificationSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsPushNotificationSelectedProvider", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsPushNotificationSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsPushNotificationSelectedProvider", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsSmsProvidersTwilio(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsSmsProvidersTwilio", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsSmsProvidersTwilio(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsSmsProvidersTwilio", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsSmsSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsSmsSelectedProvider", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsSmsSelectedProvider(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsSmsSelectedProvider", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianFactorsSmsTemplates(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetGuardianFactorsSmsTemplates", "", "")
	}, "read:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactorsSmsTemplates(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactorsSmsTemplates", "", "")
	}, "update:guardian_factors")
}
func (a mgmtAPI) SetGuardianFactor(w http.ResponseWriter, r *http.Request, name mgmtapi.SetGuardianFactorParamsName) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetGuardianFactor", "", string(name))
	}, "update:guardian_factors")
}
func (a mgmtAPI) GetGuardianPolicies(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "GetGuardianPolicies", "", "") }, "read:mfa_policies")
}
func (a mgmtAPI) SetGuardianPolicies(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "SetGuardianPolicies", "", "") }, "update:mfa_policies")
}
func (a mgmtAPI) GetGuardianSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "GetGuardianSettings", "", "") }, "read:tenant_settings")
}
func (a mgmtAPI) SetGuardianSettings(w http.ResponseWriter, r *http.Request) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "SetGuardianSettings", "", "") }, "update:tenant_settings")
}
func (a mgmtAPI) GetAuthenticationMethods(w http.ResponseWriter, r *http.Request, id string, params mgmtapi.GetAuthenticationMethodsParams) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetAuthenticationMethods", id, "")
	}, "read:authentication_methods")
}
func (a mgmtAPI) DeleteAuthenticationMethods(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "DeleteAuthenticationMethods", id, "")
	}, "delete:authentication_methods")
}
func (a mgmtAPI) CreateAuthenticationMethods(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "CreateAuthenticationMethods", id, "")
	}, "create:authentication_methods")
}
func (a mgmtAPI) SetAuthenticationMethods(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "SetAuthenticationMethods", id, "")
	}, "update:authentication_methods")
}
func (a mgmtAPI) GetAuthenticationMethod(w http.ResponseWriter, r *http.Request, id string, authenticationMethodId string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "GetAuthenticationMethod", id, authenticationMethodId)
	}, "read:authentication_methods")
}
func (a mgmtAPI) DeleteAuthenticationMethod(w http.ResponseWriter, r *http.Request, id string, authenticationMethodId string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "DeleteAuthenticationMethod", id, authenticationMethodId)
	}, "delete:authentication_methods")
}
func (a mgmtAPI) UpdateAuthenticationMethod(w http.ResponseWriter, r *http.Request, id string, authenticationMethodId string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "UpdateAuthenticationMethod", id, authenticationMethodId)
	}, "update:authentication_methods")
}
func (a mgmtAPI) DeleteUserAuthenticators(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "DeleteUserAuthenticators", id, "")
	}, "delete:guardian_enrollments")
}
func (a mgmtAPI) GetUserEnrollments(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "GetUserEnrollments", id, "") }, "read:users")
}
func (a mgmtAPI) CreateUserRememberBrowser(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "CreateUserRememberBrowser", id, "")
	}, "update:users")
}
func (a mgmtAPI) DeleteUserMultifactor(w http.ResponseWriter, r *http.Request, id string, provider mgmtapi.DeleteUserMultifactorParamsProvider) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.MFAOperation(w, r, "DeleteUserMultifactor", id, string(provider))
	}, "update:users")
}
func (a mgmtAPI) CreateUserRecoveryCode(w http.ResponseWriter, r *http.Request, id string) {
	a.mfaScoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.MFAOperation(w, r, "CreateUserRecoveryCode", id, "") }, "update:users")
}

// MFA endpoints require both the signed token scope and the currently persisted
// client grant, so revocation applies immediately to enrollment management.
func (a mgmtAPI) mfaScoped(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc, scopes ...string) {
	caller, ok := mgmt.CallerFrom(r.Context())
	if ok && caller.Kind == mgmt.M2M {
		res, _ := tenant.FromContext(r.Context())
		aud := tenant.ManagementAPIIdentifier(res.Tenant, a.h.BaseDomain)
		grant, err := a.h.Store.ClientGrants().Find(r.Context(), res.Tenant.ID, caller.ClientID, aud, store.SubjectTypeClient)
		if errors.Is(err, store.ErrNotFound) {
			mgmt.WriteError(w, 403, "insufficient_scope", "Insufficient scope")
			return
		}
		if err != nil {
			mgmt.Fail(w, err)
			return
		}
		live := grant.EffectiveScopes(tenantsetup.ManagementAPIScopes)
		for _, scope := range scopes {
			if !slices.Contains(live, scope) {
				mgmt.WriteError(w, 403, "insufficient_scope", "Insufficient scope")
				return
			}
		}
	}
	scopedAll(w, r, fn, scopes...)
}
