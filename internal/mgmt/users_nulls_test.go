package mgmt_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPatchUserNulls(t *testing.T) {
	for _, tc := range []struct {
		field, old, verification string
	}{
		{field: "email", old: "primary@example.test", verification: "email_verified"},
		{field: "phone_number", old: "+14155550100", verification: "phone_verified"},
		{field: "username", old: "primary"},
		{field: "name", old: "Primary User"},
		{field: "given_name", old: "Primary"},
		{field: "family_name", old: "User"},
		{field: "nickname", old: "Pri"},
		{field: "picture", old: "https://example.test/photo"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := t.Context()
			e.conn.Extra = map[string]any{"attributes": map[string]any{
				"phone_number": identifierOptions("optional"),
				"username":     identifierOptions("optional"),
			}}
			if err := e.st.Connections().Update(ctx, e.conn); err != nil {
				t.Fatal(err)
			}
			// A flexible username can be present on an existing user even
			// though the Management create route uses requires_username.
			u := &store.User{
				TenantID: e.tn.ID, UserID: "auth0|primary", Email: "primary@example.test", EmailVerified: true,
				PhoneNumber: "+14155550100", PhoneVerified: true, Username: "primary",
				Name: "Primary User", GivenName: "Primary", FamilyName: "User", Nickname: "Pri", Picture: "https://example.test/photo",
				Identities: []store.Identity{
					{Provider: store.StrategyDatabase, Connection: dbConn, UserID: "primary"},
					{Provider: store.StrategyDatabase, Connection: dbConn, UserID: "secondary", ProfileData: map[string]any{
						"email": "secondary@example.test", "email_verified": true, "username": "secondary", "phone_number": "+14155550101",
					}},
				},
			}
			if err := e.st.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			if w, before := e.get(t, u.UserID, ""); w.Code != 200 || before[tc.field] != tc.old {
				t.Fatalf("initial %s = %d %s", tc.field, w.Code, w.Body)
			}
			patch := map[string]any{tc.field: nil}
			if tc.verification != "" {
				patch[tc.verification] = true
			}
			w, body := e.patch(t, u.UserID, patch)
			if w.Code != 200 {
				t.Fatalf("clear %s = %d %s", tc.field, w.Code, w.Body)
			}
			if _, exists := body[tc.field]; exists {
				t.Errorf("cleared %s appears in PATCH response", tc.field)
			}
			if tc.verification != "" {
				if _, exists := body[tc.verification]; exists {
					t.Errorf("%s appears without a value", tc.verification)
				}
			}
			w, body = e.get(t, u.UserID, "")
			if _, exists := body[tc.field]; w.Code != 200 || exists {
				t.Errorf("GET after clearing %s = %d %s", tc.field, w.Code, w.Body)
			}
			stored, err := e.st.Users().Get(ctx, e.tn.ID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(stored.Identities, u.Identities) {
				t.Errorf("identity data changed when clearing %s", tc.field)
			}
			switch tc.field {
			case "email", "username":
				if _, err := e.st.Users().FindByLogin(ctx, e.tn.ID, dbConn, tc.old); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("cleared %s is still indexed: %v", tc.field, err)
				}
				if match, err := e.st.Users().FindByLogin(ctx, e.tn.ID, dbConn, "secondary@example.test"); err != nil || match.UserID != u.UserID {
					t.Errorf("linked login was removed: %v", err)
				}
			case "phone_number":
				if stored.PhoneNormalized != "" || stored.PhoneVerified {
					t.Error("phone normalization or verification survived clearing")
				}
				if users, err := e.st.Phone().FindUsersByPhone(ctx, e.tn.ID, dbConn, tc.old); err != nil || len(users) != 0 {
					t.Errorf("cleared phone is still indexed: %d users, %v", len(users), err)
				}
			}
			if tc.field == "email" && stored.EmailVerified {
				t.Error("email verification survived clearing")
			}
		})
	}

	for _, tc := range []struct {
		name, field, email, username, phone string
		requiresUsername                    bool
		attrs                               map[string]any
	}{
		{name: "legacy email", field: "email", email: "primary@example.test"},
		{name: "flexible email required", field: "email", email: "primary@example.test", phone: "+14155550100", attrs: map[string]any{
			"email": identifierOptions("required"), "phone_number": identifierOptions("optional"),
		}},
		{name: "legacy username", field: "username", email: "primary@example.test", username: "primary", requiresUsername: true},
		{name: "flexible username required", field: "username", email: "primary@example.test", username: "primary", attrs: map[string]any{
			"username": identifierOptions("required"),
		}},
		{name: "phone required", field: "phone_number", phone: "+14155550100", email: "primary@example.test", attrs: map[string]any{
			"phone_number": identifierOptions("required"),
		}},
		{name: "required phone with phone login disabled", field: "phone_number", phone: "+14155550100", email: "primary@example.test", attrs: map[string]any{
			"phone_number": map[string]any{"identifier": map[string]any{"active": false}, "signup": map[string]any{"status": "required"}},
		}},
		{name: "last active identifier", field: "phone_number", phone: "+14155550100", email: "primary@example.test", attrs: map[string]any{
			"phone_number": identifierOptions("optional"), "email": map[string]any{"identifier": map[string]any{"active": false}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := t.Context()
			e.conn.RequiresUsername = tc.requiresUsername
			e.conn.Extra = map[string]any{"attributes": tc.attrs}
			if err := e.st.Connections().Update(ctx, e.conn); err != nil {
				t.Fatal(err)
			}
			u := &store.User{
				TenantID: e.tn.ID, UserID: "auth0|primary", Email: tc.email, Username: tc.username, PhoneNumber: tc.phone, Name: "Original",
				Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: dbConn, UserID: "primary"}},
			}
			if err := e.st.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}
			w, body := e.patch(t, u.UserID, map[string]any{tc.field: nil, "name": "Updated"})
			wantUserError(t, tc.name, w, body, 400, "invalid_body", "")
			stored, err := e.st.Users().Get(ctx, e.tn.ID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.Name != "Original" || stored.Email != tc.email || stored.Username != tc.username || stored.PhoneNumber != tc.phone {
				t.Error("refused clear changed the profile")
			}
		})
	}

	t.Run("preserve linked-only connection refusal", func(t *testing.T) {
		e := newUsersEnv(t)
		other, _ := e.legacy(t, "OtherDb", true, nil)
		id := e.mustCreate(t, map[string]any{"email": "primary@example.test"})["user_id"].(string)
		linked := e.mustCreate(t, map[string]any{"email": "secondary@example.test", "connection": other.Name})["user_id"].(string)
		e.mustLink(t, id, linked)
		w, body := e.patch(t, id, map[string]any{"given_name": nil, "connection": other.Name})
		wantUserError(t, "linked-only target", w, body, 400, "inexistent_connection", "")
	})

	t.Run("legacy database keeps its email", func(t *testing.T) {
		e := newUsersEnv(t)
		conn, exec := e.legacy(t, "LegacyDb", false, nil)
		conn.Extra = phoneIdentifierOptions()
		if err := e.st.Connections().Update(t.Context(), conn); err != nil {
			t.Fatal(err)
		}
		u := &store.User{
			TenantID: e.tn.ID, UserID: "auth0|legacy", Email: "primary@example.test", PhoneNumber: "+14155550100",
			Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: conn.Name, UserID: "legacy"}},
		}
		if err := e.st.Users().Create(t.Context(), u); err != nil {
			t.Fatal(err)
		}
		w, body := e.patch(t, u.UserID, map[string]any{"email": nil})
		wantUserError(t, "legacy email", w, body, 400, "invalid_body", "")
		if len(exec.Requests()) != 0 {
			t.Error("refused clear invoked a legacy script")
		}
	})

	t.Run("non-nullable fields", func(t *testing.T) {
		e := newUsersEnv(t)
		id := e.mustCreate(t, map[string]any{"email": "primary@example.test"})["user_id"].(string)
		for _, field := range []string{"password", "blocked", "email_verified", "phone_verified", "verify_email", "verify_phone_number", "connection", "client_id"} {
			w, body := e.patch(t, id, map[string]any{field: nil})
			wantUserError(t, field, w, body, 400, "invalid_body", "")
		}
	})

	t.Run("email clear invalidates tickets", func(t *testing.T) {
		e := newUsersEnv(t)
		e.conn.Extra = phoneIdentifierOptions()
		if err := e.st.Connections().Update(t.Context(), e.conn); err != nil {
			t.Fatal(err)
		}
		id := e.mustCreate(t, map[string]any{"email": "primary@example.test", "phone_number": "+14155550100", "verify_email": false})["user_id"].(string)
		w, body := e.verifyTicket(t, map[string]any{"user_id": id})
		if w.Code != 201 {
			t.Fatalf("verification ticket = %d %s", w.Code, w.Body)
		}
		verifyRaw := verifyTicketURL.FindStringSubmatch(body["ticket"].(string))[1]
		e.verificationTicket(t, body["ticket"].(string))
		w, body = e.passwordTicket(t, map[string]any{"user_id": id, "mark_email_as_verified": true})
		if w.Code != 201 {
			t.Fatalf("reset ticket = %d %s", w.Code, w.Body)
		}
		resetRaw := resetTicketURL.FindStringSubmatch(body["ticket"].(string))[1]
		if w, _ := e.patch(t, id, map[string]any{"email": nil}); w.Code != 200 {
			t.Fatalf("clear email = %d %s", w.Code, w.Body)
		}
		if _, err := e.st.EmailVerificationTickets().GetByTokenHash(t.Context(), e.tn.ID, secrets.HashToken(verifyRaw)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("verification ticket survived: %v", err)
		}
		if _, err := e.st.PasswordResetTickets().GetByTokenHash(t.Context(), e.tn.ID, secrets.HashToken(resetRaw)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("password reset ticket survived: %v", err)
		}
	})
}

func identifierOptions(status string) map[string]any {
	return map[string]any{"identifier": map[string]any{"active": true}, "signup": map[string]any{"status": status}}
}

type beforeUserPatchTx struct {
	store.Store
	before func(context.Context) error
}

func (s beforeUserPatchTx) WithTx(ctx context.Context, fn func(store.Store) error) error {
	if err := s.before(ctx); err != nil {
		return err
	}
	return s.Store.WithTx(ctx, fn)
}

func TestPatchUserPhoneClearBeforeLegacyVerification(t *testing.T) {
	for _, tc := range []struct {
		field, value, script string
	}{
		{"email", "replacement@example.test", store.ScriptChangeEmail},
		{"password", "replacement pass 2", store.ScriptChangePassword},
	} {
		t.Run(tc.field, func(t *testing.T) {
			e := newUsersEnv(t)
			ctx := t.Context()
			conn, exec := e.legacy(t, "LegacyDb", false, map[string]func([]any) (any, error){
				tc.script: func([]any) (any, error) { return true, nil },
			})
			conn.Extra = phoneIdentifierOptions()
			if err := e.st.Connections().Update(ctx, conn); err != nil {
				t.Fatal(err)
			}
			u := &store.User{
				TenantID: e.tn.ID, UserID: "auth0|legacy", Email: "old@example.test", Name: "Original",
				PhoneNumber: "+14155550100", PhoneVerified: true,
				Identities: []store.Identity{{Provider: store.StrategyDatabase, Connection: conn.Name, UserID: "legacy"}},
			}
			if err := e.st.Users().Create(ctx, u); err != nil {
				t.Fatal(err)
			}

			// Commit a concurrent phone clear after preflight and before the
			// first PATCH takes the user lock.
			var cleared *store.User
			e.h.Store = beforeUserPatchTx{Store: e.st, before: func(ctx context.Context) error {
				return e.st.WithTx(ctx, func(tx store.Store) error {
					current, err := tx.Users().GetForUpdate(ctx, e.tn.ID, u.UserID)
					if err != nil {
						return err
					}
					current.PhoneNumber, current.PhoneNormalized, current.PhoneVerified = "", "", false
					if err := tx.Users().Update(ctx, current); err != nil {
						return err
					}
					cleared, err = tx.Users().Get(ctx, e.tn.ID, u.UserID)
					return err
				})
			}}
			w, body := e.patch(t, u.UserID, map[string]any{tc.field: tc.value, "name": "Rejected", "verify_phone_number": true})
			wantUserError(t, "phone cleared before locked validation", w, body, 400, "invalid_body", "")
			if len(exec.Requests()) != 0 {
				t.Error("refused PATCH called the legacy database script")
			}
			after, err := e.st.Users().Get(ctx, e.tn.ID, u.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if cleared == nil || cleared.PhoneNumber != "" || !reflect.DeepEqual(after, cleared) {
				t.Error("profile differs from the concurrent phone clear")
			}
		})
	}
}
