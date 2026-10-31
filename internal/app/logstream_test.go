package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

func TestAppLogStreamDeliveryAndShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer func() { close(release); server.Close() }()
	cfg := &config.Config{Server: testServer, Storage: config.Storage{DSN: "memory://"}}
	cfg.Server.Listen = "127.0.0.1:0"
	cfg.Logs.Streams.AllowPrivateNetworks = true
	cfg.Logs.Streams.AllowInsecureHTTP = true
	db := memory.NewWithClock(func() time.Time { return time.Now().Add(-3 * time.Second) })
	a, err := build(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), db, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.logStreams == nil {
		t.Fatal("stream worker was not wired")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = db.Logs().CreateLogStream(ctx, &store.LogStream{TenantID: "t", ID: "s", Type: "http", Status: "active", Sink: map[string]any{"httpEndpoint": server.URL}}); err != nil {
		t.Fatal(err)
	}
	if err = db.Logs().AppendLogs(ctx, []store.LogEvent{{TenantID: "t", Type: "s", Date: time.Now(), Body: []byte(`{"type":"s"}`)}}, nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx) }()
	select {
	case <-started:
	case err := <-done:
		t.Fatal("serve stopped before delivery", err)
	case <-time.After(5 * time.Second):
		t.Fatal("configured HTTP/private opt-ins did not reach worker")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("app did not cancel in-flight stream delivery")
	}
	s, err := db.Logs().GetLogStream(context.Background(), "t", "s")
	if err != nil || s.Checkpoint != 0 {
		t.Fatal("cancelled delivery acknowledged", s, err)
	}
}
