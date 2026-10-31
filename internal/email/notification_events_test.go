package email

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestNotificationFailureEvents(t *testing.T) {
	for _, tc := range []struct {
		name                                                               string
		stored, native, success, disabled, verification, synthetic, custom bool
	}{
		{name: "legacy fallback failure"}, {name: "stored fallback failure", stored: true},
		{name: "legacy native failure", native: true}, {name: "stored native failure", native: true, stored: true},
		{name: "success", success: true}, {name: "disabled", stored: true, disabled: true},
		{name: "verification legacy", verification: true}, {name: "verification stored", verification: true, stored: true},
		{name: "synthetic", synthetic: true, stored: true}, {name: "custom enqueued", custom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, st, w, fallback, factory, s := emailServiceFixture(t)
			recorder := logs.NewRecorder(st, logs.Config{}, slog.New(slog.DiscardHandler))
			ctx = logs.WithRecorder(logscrub.WithCredentials(ctx, "q"), recorder)
			if !tc.success {
				fallback.err = errors.New(`private error {"password":"nested"}`)
				factory.sendErr = fallback.err
			}
			if tc.native || tc.custom {
				name := "sendgrid"
				if tc.custom {
					name = "custom"
					s.Actions = &customQueue{}
				}
				if err := st.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "tenant-a", Name: name, Enabled: true, DefaultFrom: "sender@example.test", SealedCredentials: providerSecret(t, w, "tenant-a", name, "z")}, 0); err != nil {
					t.Fatal(err)
				}
			}
			kind := "welcome_email"
			if tc.verification {
				kind = "verify_email"
			}
			var err error
			if tc.stored {
				if e := st.Users().Create(ctx, &store.User{TenantID: "tenant-a", UserID: "user-a", Email: "user@example.test"}); e != nil {
					t.Fatal(e)
				}
				if e := st.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "tenant-a", Name: kind, Fields: map[string]any{"enabled": !tc.disabled, "body": "<p>private body</p>", "subject": "private subject"}}, 0); e != nil {
					t.Fatal(e)
				}
				if tc.synthetic {
					err = s.SendTest(ctx, "tenant-a", kind, "operator@example.test")
				} else {
					err = s.Send(ctx, Event{TenantID: "tenant-a", UserID: "user-a", ClientID: "", Template: kind, URL: "https://example.test/?secret=link"})
				}
			} else {
				msg := Message{UserID: "user-a", ClientID: "client-q", OrganizationID: "org-a", Type: kind, To: "private@example.test", Subject: "private subject", Text: "private body"}
				if tc.native {
					msg.ClientID = "client-z"
				}
				if tc.custom {
					msg.UserID, msg.ClientID, msg.OrganizationID = "", "", ""
				}
				err = s.SendMessage(ctx, "tenant-a", msg)
			}
			want := !tc.success && !tc.disabled && !tc.verification && !tc.synthetic && !tc.custom
			if want && err == nil {
				t.Fatal("failure expected")
			}
			if err := recorder.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			events, _, err := st.Logs().SearchLogs(context.Background(), "tenant-a", nil, store.LogPage{PerPage: 20})
			if err != nil {
				t.Fatal(err)
			}
			if !want {
				if len(events) != 0 {
					t.Fatalf("unexpected events=%+v", events)
				}
				return
			}
			if len(events) != 1 || events[0].Type != "fn" || events[0].UserID != "user-a" {
				t.Fatalf("events=%+v", events)
			}
			var doc map[string]any
			_ = json.Unmarshal(events[0].Body, &doc)
			if doc["date"] == "" || doc["type"] != "fn" {
				t.Fatalf("schema=%s", events[0].Body)
			}
			if !tc.stored && (events[0].ClientID != "client-"+logscrub.Marker || events[0].OrganizationID != "org-a") {
				t.Fatalf("metadata=%s", events[0].Body)
			}
			for _, v := range []string{"private", "nested", "link", "secret="} {
				if strings.Contains(string(events[0].Body), v) {
					t.Fatalf("leak=%s", events[0].Body)
				}
			}
		})
	}
}
