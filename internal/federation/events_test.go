package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/script"
	"github.com/zeroauthy/zeroauthy/internal/logscrub"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

type maskAttemptStore struct {
	store.Store
	check func(context.Context)
}

func (s maskAttemptStore) Federation() store.Federation {
	return maskAttemptRepository{s.Store.Federation(), s.check}
}

type maskAttemptRepository struct {
	store.Federation
	check func(context.Context)
}

func (s maskAttemptRepository) ClaimAttempt(ctx context.Context, _, _, _, _ string, _ time.Time) (*store.FederationAttempt, error) {
	s.check(ctx)
	return nil, store.ErrNotFound
}
func TestFederationCallbackCodeMaskedAtEntry(t *testing.T) {
	for _, code := range []string{"callback-code", "abc", "猫"} {
		t.Run(code, func(t *testing.T) {
			checked := false
			st := maskAttemptStore{memory.New(), func(ctx context.Context) {
				checked = true
				if logscrub.MaskText(ctx, code) != logscrub.Marker {
					t.Fatal("code not registered before store/provider work")
				}
			}}
			svc := FlowService{Store: st}
			_, _ = svc.Complete(context.Background(), CompleteInput{Tenant: &store.Tenant{ID: "t"}, CookieValue: "cookie", Params: CallbackParams{State: "state", Code: code}})
			if !checked {
				t.Fatal("entry never reached")
			}
		})
	}
}

type maskScriptExecutor struct {
	output   *bytes.Buffer
	password string
}

func (e maskScriptExecutor) Execute(ctx context.Context, _ script.Request) (json.RawMessage, error) {
	log := slog.New(logscrub.Handler(slog.NewJSONHandler(e.output, nil)))
	log.InfoContext(ctx, "federation profile script", "output", map[string]any{e.password: e.password})
	return json.RawMessage(`{"user_id":"mapped"}`), nil
}
func (maskScriptExecutor) Close() error { return nil }
func TestFederationScriptCredentialMasked(t *testing.T) {
	for _, password := range []string{"submitted-password", "abc", "猫"} {
		t.Run(password, func(t *testing.T) {
			ps, cfg, in := oauthFixture(t)
			var sink bytes.Buffer
			ps.WithScripts(maskScriptExecutor{&sink, password})
			ctx := logscrub.WithCredentials(logscrub.WithValues(context.Background(), password), password)
			if _, err := ps.For(cfg).Exchange(ctx, in); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(sink.String(), password) || !strings.Contains(sink.String(), logscrub.Marker) {
				t.Fatalf("script context lost masks: %s", sink.String())
			}
		})
	}
}
