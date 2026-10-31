package server

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

func TestAuthenticationRecorderWiring(t *testing.T) {
	st := memory.New()
	defer st.Close()
	ctx := context.Background()
	f, err := seed.Parse([]byte(testSeed))
	if err != nil {
		t.Fatal(err)
	}
	wrapper, _ := keys.NewLocalWrapper(bytes.Repeat([]byte{5}, 32))
	if err = seed.Apply(ctx, st, f, nil, wrapper); err != nil {
		t.Fatal(err)
	}
	km := keys.NewManager(st.SigningKeys(), wrapper)
	tn, _ := st.Tenants().GetByName(ctx, "acme")
	if err = km.Ensure(ctx, tn.ID); err != nil {
		t.Fatal(err)
	}
	recorder := logs.NewRecorder(st, logs.Config{}, slog.New(slog.DiscardHandler))
	h := New(Deps{Store: st, Keys: km, Wrapper: wrapper, Resolver: tenant.NewResolver(st.Tenants(), "", false), Sessions: &session.Manager{Store: st}, Recorder: recorder, Log: slog.New(slog.DiscardHandler)})
	r := httptest.NewRequest("POST", "https://acme.example.test/oauth/token", strings.NewReader("grant_type=client_credentials&client_id=m2m&client_secret=s3cret&audience=https%3A%2F%2Fapi.acme.test"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, r)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body)
	}
	if err = recorder.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	events, _, err := st.Logs().SearchLogs(ctx, tn.ID, nil, store.LogPage{PerPage: 1})
	if err != nil || len(events) != 1 || events[0].Type != "seccft" || events[0].ClientID != "m2m" {
		t.Fatal(events, err)
	}
}
