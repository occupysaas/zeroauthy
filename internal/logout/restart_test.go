package logout

import (
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestDeliverySurvivesRestart(t *testing.T) {
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("logout_token") == "" {
			t.Error("token missing after restart")
		}
		w.WriteHeader(200)
	}))
	defer receiver.Close()
	dsn := "sqlite://" + filepath.Join(t.TempDir(), "logout.db")
	st, err := sqlstore.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := st.Tenants().Create(t.Context(), &store.Tenant{ID: "t", Name: "t", CanonicalHost: "tenant.example", Domains: []string{"tenant.example"}}); err != nil {
		t.Fatal(err)
	}
	wrapper, _ := keys.NewLocalWrapper([]byte(secrets.RandomString(32)))
	manager := keys.NewManager(st.SigningKeys(), wrapper)
	if err := manager.Ensure(t.Context(), "t"); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC()
	service := &Service{Store: st, Wrapper: wrapper, Keys: manager, Now: func() time.Time { return at }, HTTP: receiver.Client(), AllowPrivateNetworks: true}
	job := deliveryJob(t, service, receiver.URL)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlstore.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// The abandoned worker's lease expires; a new service and key manager claim it.
	at = at.Add(2 * time.Minute)
	jobs, err := reopened.Actions().ClaimJobs(t.Context(), at, time.Minute, 1)
	if err != nil || len(jobs) != 1 || jobs[0].ID != job.ID {
		t.Fatalf("restart claim count=%d err=%v", len(jobs), err)
	}
	restarted := &Service{Store: reopened, Wrapper: wrapper, Keys: keys.NewManager(reopened.SigningKeys(), wrapper), Now: func() time.Time { return at }, HTTP: receiver.Client(), AllowPrivateNetworks: true}
	next := restarted.Deliver(t.Context(), &jobs[0])
	if next == nil || next.Status != "done" {
		t.Fatal("persisted job was not delivered")
	}
	if err := reopened.Actions().FinishJob(t.Context(), next, jobs[0].LeaseUntil); err != nil {
		t.Fatal(err)
	}
	stored, err := reopened.Actions().GetJob(t.Context(), "t", job.ID)
	if err != nil || stored.Status != "done" {
		t.Fatal("terminal delivery state not persisted")
	}
}
