package identity

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/customdb"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// withConfig seals cfg into conn and gives db a client that can open it and
// a log captured in the returned buffer.
func withConfig(t *testing.T, db *Database, conn *store.Connection, cfg map[string]string) *bytes.Buffer {
	t.Helper()
	key := make([]byte, 32)
	w, err := keys.NewLocalWrapper(key)
	if err != nil {
		t.Fatal(err)
	}
	db.Scripts.Wrapper = w
	if conn.ConfigurationSealed, err = keys.SealConnectionConfig(w, conn.TenantID, conn.ID, cfg); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	db.Log = slog.New(slog.NewJSONHandler(&buf, nil))
	return &buf
}

func TestLoginProfileKeepsConfigurationValues(t *testing.T) {
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		return map[string]any{"user_id": "1", "email": "a@b.test", "name": "user"}, nil
	}})
	withConfig(t, db, conn, map[string]string{"k": "user"})
	u, err := db.Login(context.Background(), conn, "a@b.test", "pw")
	if err != nil || u.Name != "user" {
		t.Fatalf("user = %+v, err = %v", u, err)
	}
}

func TestSignupValidationCodeKeptWithShortConfigurationValue(t *testing.T) {
	s := &signupScripts{users: map[string]*legacyUser{}}
	f := s.funcs()
	f[store.ScriptCreate] = func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindValidation, Code: "user_exists", Message: "exists"}
	}
	db, conn, _ := legacyConn(t, f)
	withConfig(t, db, conn, map[string]string{"k": "user"})
	if _, err := db.Signup(context.Background(), conn, SignupInput{Email: "n@b.test", Password: "long enough pw"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestScriptErrorLogIsMasked(t *testing.T) {
	const secret = "hunter2-s3cret"
	db, conn, _ := legacyConn(t, scripts{store.ScriptLogin: func([]any) (any, error) {
		return nil, &customdb.ScriptError{Kind: customdb.KindError, Message: "cannot connect with " + secret}
	}})
	buf := withConfig(t, db, conn, map[string]string{"k": secret})
	_, err := db.Login(context.Background(), conn, "a@b.test", "pw")
	if err == nil || !strings.Contains(err.Error(), secret) {
		t.Fatalf("returned error must stay unmodified: %v", err)
	}
	if out := buf.String(); strings.Contains(out, secret) || !strings.Contains(out, customdb.Mask) {
		t.Fatalf("log = %s", out)
	}
}
