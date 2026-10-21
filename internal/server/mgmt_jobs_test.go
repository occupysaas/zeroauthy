package server

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/jobs"
	"github.com/zeroauthy/zeroauthy/internal/login"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
)

// jobsSeed adds clients that hold one job-related scope each.
var jobsSeed = func() string {
	clients := ""
	grants := ""
	for _, c := range []struct{ id, scope string }{
		{"jobsread", "read:users"}, {"jobscreate", "create:users"}, {"jobsupdate", "update:users"}, {"jobsnone", "read:clients"},
	} {
		clients += "      - {client_id: " + c.id + ", app_type: non_interactive, client_secret: jobs-s3cret, grant_types: [client_credentials]}\n"
		grants += "      - {client_id: " + c.id + ", audience: \"https://acme.example.test/api/v2/\", scopes: [\"" + c.scope + "\"]}\n"
	}
	s := strings.Replace(usersSeed, "      - {client_id: usersro,", clients+"      - {client_id: usersro,", 1)
	return strings.Replace(s, "    client_grants:\n", "    client_grants:\n"+grants, 1)
}()

func newJobsAPI(t *testing.T, adjust func(*Deps)) *usersAPI {
	t.Helper()
	h, st := newMgmtEnvOn(t, memory.New(), jobsSeed, adjust)
	return &usersAPI{t: t, h: h, st: st, token: clientToken(t, h, "acme.example.test", acmeMgmtAPI, "users", "users-s3cret")}
}

func (a *usersAPI) tokenFor(id string) string {
	return clientToken(a.t, a.h, "acme.example.test", acmeMgmtAPI, id, "jobs-s3cret")
}

const jobsBase = "https://acme.example.test/api/v2/jobs"

func TestJobScopes(t *testing.T) {
	a := newJobsAPI(t, nil)
	rec, out := a.do("POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": "j@example.test", "password": "first horse 1"})
	if rec.Code != 201 {
		t.Fatalf("create user = %d %s", rec.Code, rec.Body)
	}
	body := map[string]any{"user_id": out["user_id"]}
	rec, job := a.doAs(a.tokenFor("jobsupdate"), "POST", jobsBase+"/verification-email", body)
	if rec.Code != 201 {
		t.Fatalf("verification-email with update:users = %d %s", rec.Code, rec.Body)
	}
	id := job["id"].(string)

	for _, c := range []struct {
		client, method, target string
		want                   int
	}{
		{"jobsread", "POST", "/verification-email", 403},
		{"jobscreate", "POST", "/verification-email", 403},
		{"jobsnone", "POST", "/verification-email", 403},
		{"jobsread", "GET", "/" + id, 200},
		{"jobscreate", "GET", "/" + id, 200},
		{"jobsupdate", "GET", "/" + id, 403},
		{"jobsnone", "GET", "/" + id, 403},
		{"jobsread", "GET", "/" + id + "/errors", 204},
		{"jobscreate", "GET", "/" + id + "/errors", 204},
		{"jobsupdate", "GET", "/" + id + "/errors", 403},
		{"jobsnone", "GET", "/" + id + "/errors", 403},
	} {
		var b any
		if c.method == "POST" {
			b = body
		}
		if rec, _ := a.doAs(a.tokenFor(c.client), c.method, jobsBase+c.target, b); rec.Code != c.want {
			t.Errorf("%s %s as %s = %d %s, want %d", c.method, c.target, c.client, rec.Code, rec.Body, c.want)
		}
	}
}

type countingMailer struct {
	mu   sync.Mutex
	sent []email.Message
}

func (m *countingMailer) Send(_ context.Context, msg email.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	return nil
}

func (m *countingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// A verification-email job, over HTTP, is picked up by a worker, sends the
// email once and reads completed.
func TestVerificationEmailJobEndToEnd(t *testing.T) {
	mail := &countingMailer{}
	var runner *jobs.Runner
	var notified atomic.Int32
	a := newJobsAPI(t, func(d *Deps) {
		d.Mailer = mail
		d.JobNotify = func() { notified.Add(1); runner.Notify() }
	})
	runner = &jobs.Runner{
		Store: a.st, Workers: 2, LeaseFor: time.Second, Poll: time.Hour,
		Processors: map[store.JobType]jobs.Processor{
			store.JobVerificationEmail: jobs.VerifyEmail{Sender: &login.VerificationMailer{Store: a.st, Mailer: mail, BaseDomain: "example.test"}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	rec, u := a.do("POST", usersBase, map[string]any{"connection": "Username-Password-Authentication", "email": "e2e@example.test", "password": "first horse 1"})
	if rec.Code != 201 {
		t.Fatalf("create user = %d %s", rec.Code, rec.Body)
	}
	before := mail.count()
	rec, job := a.do("POST", jobsBase+"/verification-email", map[string]any{"user_id": u["user_id"]})
	if rec.Code != 201 || notified.Load() != 1 {
		t.Fatalf("create job = %d %s, notified %d", rec.Code, rec.Body, notified.Load())
	}
	target := jobsBase + "/" + url.PathEscape(job["id"].(string))
	deadline := time.Now().Add(5 * time.Second)
	var got map[string]any
	for {
		_, got = a.do("GET", target, nil)
		if got["status"] == "completed" || got["status"] == "failed" || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got["status"] != "completed" {
		t.Fatalf("job = %v, want completed", got)
	}
	time.Sleep(50 * time.Millisecond)
	if n := mail.count() - before; n != 1 {
		t.Errorf("%d emails sent, want 1", n)
	}
}
