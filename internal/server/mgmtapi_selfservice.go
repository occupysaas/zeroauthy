package server

import (
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/gen/mgmtapi"
)

// Self-service SSO and connection profile routes (Plan 37c Phase B).

func (a mgmtAPI) ListSelfServiceProfiles(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListSelfServiceProfilesParams) {
	scoped(w, r, a.h.ListSelfServiceProfiles, "read:self_service_profiles")
}
func (a mgmtAPI) CreateSelfServiceProfile(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateSelfServiceProfile, "create:self_service_profiles")
}
func (a mgmtAPI) GetSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetSelfServiceProfile(w, r, id) }, "read:self_service_profiles")
}
func (a mgmtAPI) UpdateSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateSelfServiceProfile(w, r, id) }, "update:self_service_profiles")
}
func (a mgmtAPI) DeleteSelfServiceProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteSelfServiceProfile(w, r, id) }, "delete:self_service_profiles")
}
func (a mgmtAPI) GetSelfServiceProfileCustomText(w http.ResponseWriter, r *http.Request, id string, language mgmtapi.SelfServiceProfileCustomTextLanguageEnum, page mgmtapi.SelfServiceProfileCustomTextPageEnum) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.GetSelfServiceProfileCustomText(w, r, id, string(language), string(page))
	}, "read:self_service_profile_custom_texts")
}
func (a mgmtAPI) SetSelfServiceProfileCustomText(w http.ResponseWriter, r *http.Request, id string, language mgmtapi.SelfServiceProfileCustomTextLanguageEnum, page mgmtapi.SelfServiceProfileCustomTextPageEnum) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) {
		a.h.SetSelfServiceProfileCustomText(w, r, id, string(language), string(page))
	}, "update:self_service_profile_custom_texts")
}
func (a mgmtAPI) CreateSsoTicket(w http.ResponseWriter, r *http.Request, id string, _ mgmtapi.CreateSsoTicketParams) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.CreateSsoTicket(w, r, id) }, "create:sso_access_tickets")
}
func (a mgmtAPI) RevokeSsoTicket(w http.ResponseWriter, r *http.Request, profileID, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.RevokeSsoTicket(w, r, profileID, id) }, "delete:sso_access_tickets")
}
func (a mgmtAPI) ListConnectionProfiles(w http.ResponseWriter, r *http.Request, _ mgmtapi.ListConnectionProfilesParams) {
	scoped(w, r, a.h.ListConnectionProfiles, "read:connection_profiles")
}
func (a mgmtAPI) CreateConnectionProfile(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.CreateConnectionProfile, "create:connection_profiles")
}
func (a mgmtAPI) GetConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnectionProfile(w, r, id) }, "read:connection_profiles")
}
func (a mgmtAPI) UpdateConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.UpdateConnectionProfile(w, r, id) }, "update:connection_profiles")
}
func (a mgmtAPI) DeleteConnectionProfile(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.DeleteConnectionProfile(w, r, id) }, "delete:connection_profiles")
}
func (a mgmtAPI) ListConnectionProfileTemplates(w http.ResponseWriter, r *http.Request) {
	scoped(w, r, a.h.ListConnectionProfileTemplates, "read:connection_profiles")
}
func (a mgmtAPI) GetConnectionProfileTemplate(w http.ResponseWriter, r *http.Request, id string) {
	scoped(w, r, func(w http.ResponseWriter, r *http.Request) { a.h.GetConnectionProfileTemplate(w, r, id) }, "read:connection_profiles")
}
