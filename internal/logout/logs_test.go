package logout

import (
	"context"
	"encoding/json"
	"github.com/zeroauthy/zeroauthy/internal/logs"
	"strings"
	"testing"
)

type recorder struct{ events []logs.Event }

func (r *recorder) Record(_ context.Context, e logs.Event) { r.events = append(r.events, e) }
func TestDeliveryOutcomeLog(t *testing.T) {
	s := queuedService(t)
	capture := &recorder{}
	s.Recorder = capture
	job := deliveryJob(t, s, "https://rp.example/logout?credential=private-value")
	job.Status = "pending"
	s.Finished(t.Context(), job)
	if len(capture.events) != 0 {
		t.Fatal("retry emitted terminal outcome")
	}
	job.Status = "done"
	s.Finished(t.Context(), job)
	if len(capture.events) != 1 || capture.events[0].Type != "oidc_backchannel_logout_succeeded" || capture.events[0].ClientID != "rp" {
		t.Fatal("wrong delivery outcome")
	}
	raw, _ := json.Marshal(capture.events)
	if strings.Contains(string(raw), "private-value") || strings.Contains(string(raw), "logout_token") || strings.Contains(string(raw), "?credential") {
		t.Fatal("delivery log leaked a URL or credential")
	}
	if capture.events[0].Details["receiver_host"] != "rp.example" {
		t.Fatal("receiver hostname absent")
	}
}

func TestUnresolvedReceiverTerminalLog(t *testing.T) {
	s := queuedService(t)
	capture := &recorder{}
	s.Recorder = capture
	job := deliveryJob(t, s, "https://{organization_name}.rp.example/logout")
	next := s.Deliver(t.Context(), job)
	if next == nil || next.Status != "failed" {
		t.Fatal("unresolved receiver must fail closed")
	}
	s.Finished(t.Context(), next)
	if len(capture.events) != 1 || capture.events[0].ClientID != "rp" || capture.events[0].Details["initiator"] != "rp-logout" {
		t.Fatal("terminal outcome missing")
	}
	if _, ok := capture.events[0].Details["receiver_host"]; ok {
		t.Fatal("unresolved hostname logged")
	}
}
