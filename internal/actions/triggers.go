package actions

import (
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
)

// Trigger IDs share the frozen inventory with Management's catalogue.
const (
	TriggerPostLogin            = "post-login"
	TriggerCredentialsExchange  = "credentials-exchange"
	TriggerPreUserRegistration  = "pre-user-registration"
	TriggerPostUserRegistration = "post-user-registration"
	TriggerPostChangePassword   = "post-change-password"
	TriggerResetPostChallenge   = "password-reset-post-challenge"
	TriggerCustomEmailProvider  = "custom-email-provider"
)

type triggerSpec struct {
	ID, Handler, ContinueHandler string
	Blocking                     bool
	API                          []string
	unsupported                  []string
}

// The frozen inventory is authoritative for handlers and API capabilities.
// In particular reset redirect.canRedirect is a local helper (D-0054), while
// challengeWith/challengeWithAny and prompt.render deliberately fail closed.
var triggerSpecs = func() map[string]triggerSpec {
	out := map[string]triggerSpec{}
	for _, t := range actionsrules.Inventory().Triggers {
		spec := triggerSpec{ID: t.ID, Handler: t.Handler, ContinueHandler: t.ContinueHandler, Blocking: t.Blocking}
		for _, member := range t.API {
			spec.API = append(spec.API, member.Name)
			if member.Support == "unsupported" {
				spec.unsupported = append(spec.unsupported, member.Name)
			}
		}
		out[t.ID] = spec
	}
	return out
}()

func handlerFor(trigger string) string { return triggerSpecs[trigger].Handler }

func (s triggerSpec) allows(op string) bool {
	return slices.Contains(s.API, op) && !slices.Contains(s.unsupported, op)
}
