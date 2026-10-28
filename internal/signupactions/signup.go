// Package signupactions adapts the Actions engine to identity's signup callbacks.
package signupactions

import (
	"context"
	"errors"
	"net/http"

	"github.com/zeroauthy/zeroauthy/internal/actions"
	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func Callbacks(e *actions.Engine, in actions.RegistrationInput) identity.SignupActions {
	if e == nil {
		return identity.SignupActions{}
	}
	return identity.SignupActions{
		Run: func(ctx context.Context, u *store.User) (*actions.Result, error) {
			in.User = u
			result, err := e.PreUserRegistration(ctx, in)
			if err != nil {
				var flow *actions.ErrFlow
				errors.As(err, &flow)
				failed := &identity.ErrSignupActionFailed{}
				if flow != nil {
					failed.ExecutionID = flow.ExecutionID
				}
				return nil, failed
			}
			return result, nil
		},
		Enqueue: func(ctx context.Context, tx store.Store, u *store.User) error {
			in.User = u
			return e.EnqueuePostUserRegistration(ctx, tx, in)
		},
	}
}

// Input copies caller-known context, including the admitted custom domain.
func Input(r *http.Request, res tenant.Resolved, client *store.Client, conn *store.Connection, body map[string]any, trustProxy bool) actions.RegistrationInput {
	in := actions.RegistrationInput{Tenant: res, Client: client, Connection: conn, Request: actions.RequestInfo{IP: httpx.ClientIP(r, trustProxy), Hostname: res.Host, Method: r.Method, Language: r.Header.Get("Accept-Language"), UserAgent: r.UserAgent(), Origin: res.Origin(), Body: body}}
	if domain := customdomain.PublicDomainFromContext(r.Context()); domain != nil {
		in.CustomDomain = domain.Domain
	}
	return in
}
