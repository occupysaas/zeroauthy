package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/logs"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMountedNotificationFailureEvent(t *testing.T) {
	var recorder *logs.AsyncRecorder
	notified := make(chan struct{}, 1)
	e := newFlowEnvSeed(t, flowSeed, func(d *Deps) {
		recorder = logs.NewRecorder(d.Store, logs.Config{}, slog.New(slog.DiscardHandler))
		d.Recorder = &notificationRecorder{Recorder: recorder, notified: notified}
		d.Mailer = &testEmailMailer{err: errors.New("private transport failure")}
	})
	req, _ := http.NewRequest("POST", e.base+"/dbconnections/change_password", strings.NewReader(`{"client_id":"spa","connection":"Username-Password-Authentication","email":"alice@flow.test"}`))
	req.Header.Set("Content-Type", "application/json")
	response, _ := mustDo(t, e.client(t), req)
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		t.Fatal("no dispatch failure event")
	}
	if err := recorder.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	tn, _ := e.st.Tenants().GetByName(context.Background(), "flow")
	events, _, err := e.st.Logs().SearchLogs(context.Background(), tn.ID, nil, store.LogPage{PerPage: 20, Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, event := range events {
		codes = append(codes, event.Type)
		if event.Type == "fn" && (event.ClientID != "spa" || event.UserID == "") {
			t.Fatalf("attribution=%s", event.Body)
		}
	}
	slices.Sort(codes)
	if !slices.Equal(codes, []string{"fn", "scpr"}) {
		t.Fatalf("events=%+v", events)
	}
	if strings.Contains(string(events[0].Body), "private") {
		t.Fatalf("leak=%s", events[0].Body)
	}
}

type notificationRecorder struct {
	logs.Recorder
	notified chan struct{}
}

func (r *notificationRecorder) Record(ctx context.Context, e logs.Event) {
	r.Recorder.Record(ctx, e)
	if e.Type == "fn" {
		r.notified <- struct{}{}
	}
}
