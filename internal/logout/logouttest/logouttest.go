// Package logouttest lets tests in trigger packages check which client and
// initiator a queued back-channel logout notification carries, rather than
// only counting jobs.
package logouttest

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/logout"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// envelopeLabel mirrors the sealing label in internal/logout. The package's
// own test seals a real job and opens it here, so a drift fails there.
const envelopeLabel = "backchannel-logout/v1"

// Notification is the part of a sealed job a trigger test asserts on.
type Notification struct {
	ClientID  string
	Initiator string
	SessionID string
}

// Open decodes every job, failing the test for a job of another kind or one
// that does not open under wrapper.
func Open(t testing.TB, wrapper keys.Wrapper, jobs []store.ActionJob) []Notification {
	t.Helper()
	out := make([]Notification, 0, len(jobs))
	for i := range jobs {
		job := &jobs[i]
		if job.Trigger != logout.JobKind {
			t.Fatalf("job %s has trigger %q, want %q", job.ID, job.Trigger, logout.JobKind)
		}
		raw, err := keys.OpenBound(wrapper, envelopeLabel, []string{job.TenantID, job.ID, logout.JobKind}, job.Sealed)
		if err != nil {
			t.Fatalf("open job %s: %v", job.ID, err)
		}
		var p struct {
			ClientID  string
			Initiator string
			Session   struct{ ID string }
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("decode job %s: %v", job.ID, err)
		}
		out = append(out, Notification{ClientID: p.ClientID, Initiator: p.Initiator, SessionID: p.Session.ID})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ClientID != out[j].ClientID {
			return out[i].ClientID < out[j].ClientID
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out
}

// RequireInitiator fails unless every job carries want and there are n jobs.
func RequireInitiator(t testing.TB, wrapper keys.Wrapper, jobs []store.ActionJob, n int, want logout.Initiator) []Notification {
	t.Helper()
	got := Open(t, wrapper, jobs)
	if len(got) != n {
		t.Fatalf("got %d logout notifications %+v, want %d", len(got), got, n)
	}
	for _, note := range got {
		if note.Initiator != string(want) {
			t.Fatalf("notification %+v has initiator %q, want %q", note, note.Initiator, want)
		}
	}
	return got
}
