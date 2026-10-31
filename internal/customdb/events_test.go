package customdb

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestPrintedCredentialsMasked(t *testing.T) {
	for _, password := range []string{"printed-password-🔑", "abc", "猫"} {
		t.Run(password, func(t *testing.T) {
			var sink syncBuffer
			log := slog.New(logscrub.Handler(slog.NewJSONHandler(&sink, nil)))
			r := newRunnerLog(t, config.CustomDB{}, log)
			client := &Client{Exec: r}
			conn := &store.Connection{TenantID: "t", ID: "c", CustomScripts: map[string]string{store.ScriptLogin: `function login(e,p,cb){console.log("printed-marker",p); console.log(JSON.stringify({[p]:p}));cb(null,{user_id:"1",email:e,name:p});setTimeout(()=>console.log("late-marker",p),30);}`}}
			var lines []string
			_, err := client.Try(context.Background(), conn, store.ScriptLogin, []any{"test@example.test", password}, func(output []string) { lines = output })
			if err != nil {
				t.Fatal(err)
			}
			if len(lines) != 2 || lines[0] != "printed-marker "+logscrub.Marker || strings.Contains(lines[1], password) {
				t.Fatalf("lines=%q", lines)
			}
			waitLog(t, &sink, "late-marker")
			out := sink.String()
			if strings.Contains(out, password) || !strings.Contains(out, logscrub.Marker) {
				t.Fatalf("script secret leaked: %s", out)
			}
		})
	}
}

func TestPrintedPasswordMaskedAtTruncation(t *testing.T) {
	var sink syncBuffer
	r := newRunnerLog(t, config.CustomDB{}, slog.New(logscrub.Handler(slog.NewJSONHandler(&sink, nil))))
	password := "credential-never-show"
	conn := &store.Connection{TenantID: "t", ID: "c", CustomScripts: map[string]string{store.ScriptLogin: `function login(e,p,cb){console.log("x".repeat(2040)+p);cb(null,{user_id:"1",email:e})}`}}
	client := Client{Exec: r}
	if _, err := client.Login(context.Background(), conn, "a@example.test", password); err != nil {
		t.Fatal(err)
	}
	waitLog(t, &sink, "custom database script")
	if strings.Contains(sink.String(), "credent") || !strings.Contains(sink.String(), logscrub.Marker) {
		t.Fatalf("credential prefix leaked: %s", sink.String())
	}
}
