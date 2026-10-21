package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// jt is a job time; the stores keep no clock, so the suites pass the claims'
// and the sweep's times explicitly.
func jt(offset time.Duration) time.Time { return ts(offset) }

func newJob(tenantID, id string, typ store.JobType) *store.Job {
	return &store.Job{
		TenantID: tenantID, ID: id, Type: typ, Status: store.JobPending,
		ConnectionID: "con_1", Connection: "Database", ExternalID: "ext-" + id,
		Params: map[string]any{
			"upsert": true, "send_completion_email": false, "n": float64(3),
			"nested": map[string]any{"a": []any{"x", float64(1), map[string]any{"b": nil}}},
		},
		Input:    []byte(`[{"email":"a@example.test"}]`),
		Progress: 2, Summary: store.JobSummary{Failed: 1, Updated: 2, Inserted: 3, Total: 6},
		StatusDetails: "details",
		Attempts:      1, LeaseOwner: "worker-0", LeaseUntil: jt(time.Minute), FirstClaimedAt: jt(time.Second),
		CreatedAt: jt(0), UpdatedAt: jt(time.Second), ExpiresAt: jt(24 * time.Hour),
		FileSize: 1234,
	}
}

// pendingJob is a job as a handler creates it.
func pendingJob(tenantID, id string, typ store.JobType, created time.Duration) *store.Job {
	return &store.Job{
		TenantID: tenantID, ID: id, Type: typ, Status: store.JobPending,
		Connection:    "Database",
		Params:        map[string]any{"k": "v"},
		CreatedAt:     jt(created),
		UpdatedAt:     jt(created),
		ExpiresAt:     jt(24 * time.Hour),
		StatusDetails: "",
	}
}

func jobErr(index int) store.JobError {
	return store.JobError{
		Index: index,
		User:  map[string]any{"email": fmt.Sprintf("u%d@example.test", index), "custom_password_hash": map[string]any{"hash": map[string]any{"value": "***"}}},
		Errors: []store.JobErrorItem{
			{Code: "DUPLICATED_USER", Message: "The user already exists.", Path: "email"},
			{Code: "OTHER", Message: "Other."},
		},
	}
}

func testJobs(t *testing.T, newStore Factory) {
	ctx := context.Background()
	const lease = time.Minute

	// claimed creates a pending job and claims it for owner at now.
	claimed := func(t *testing.T, s store.Store, id, owner string, now time.Time) *store.Job {
		t.Helper()
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_a", id, store.JobUsersImport, 0)))
		j, err := s.Jobs().Claim(ctx, owner, now, lease)
		mustNoErr(t, err)
		mustEqual(t, j.ID, id)
		return j
	}

	t.Run("CreateGet", func(t *testing.T) {
		s := open(t, newStore)
		in := newJob("ten_a", "job_1", store.JobUsersImport)
		mustNoErr(t, s.Jobs().Create(ctx, in))
		in.Params["nested"].(map[string]any)["a"].([]any)[0] = "mutated" // Create copies its input
		in.Input[0] = 'X'
		want := newJob("ten_a", "job_1", store.JobUsersImport)
		got, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, got, want)

		got.Params["nested"].(map[string]any)["a"].([]any)[0] = "mutated"
		got.Input[0] = 'X'
		again, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, again, want)

		bare := pendingJob("ten_a", "job_2", store.JobUsersExport, 0)
		bare.Params = nil
		mustNoErr(t, s.Jobs().Create(ctx, bare))
		got, err = s.Jobs().Get(ctx, "ten_a", "job_2")
		mustNoErr(t, err)
		mustEqual(t, got, bare)

		_, err = s.Jobs().Get(ctx, "ten_b", "job_1")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Jobs().Get(ctx, "ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("CreateConflict", func(t *testing.T) {
		s := open(t, newStore)
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_a", "job_1", store.JobUsersImport, 0)))
		mustErrIs(t, s.Jobs().Create(ctx, pendingJob("ten_a", "job_1", store.JobUsersExport, 0)), store.ErrConflict)
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_b", "job_1", store.JobUsersImport, 0)))
	})

	t.Run("ExpiredStayUntilSwept", func(t *testing.T) {
		s := open(t, newStore)
		old := pendingJob("ten_a", "job_old", store.JobUsersImport, 0)
		old.ExpiresAt = jt(time.Hour)
		mustNoErr(t, s.Jobs().Create(ctx, old))
		// The store keeps no clock: the job is there until DeleteExpired.
		got, err := s.Jobs().Get(ctx, "ten_a", "job_old")
		mustNoErr(t, err)
		mustEqual(t, got.ID, "job_old")
		list, total, err := s.Jobs().List(ctx, "ten_a", store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 1)
		mustEqual(t, len(list), 1)
		n, err := s.Jobs().DeleteExpired(ctx, jt(2*time.Hour))
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.Jobs().Get(ctx, "ten_a", "job_old")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ClaimSkipsExpiredPending", func(t *testing.T) {
		s := open(t, newStore)
		old := pendingJob("ten_a", "job_old", store.JobUsersImport, 0)
		old.ExpiresAt = jt(time.Hour)
		mustNoErr(t, s.Jobs().Create(ctx, old))
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_a", "job_new", store.JobUsersImport, time.Second)))
		j, err := s.Jobs().Claim(ctx, "w1", jt(2*time.Hour), lease)
		mustNoErr(t, err)
		mustEqual(t, j.ID, "job_new")
		_, err = s.Jobs().Claim(ctx, "w2", jt(2*time.Hour), lease)
		mustErrIs(t, err, store.ErrNotFound)
		// Not yet expired at its own ExpiresAt.
		j, err = s.Jobs().Claim(ctx, "w3", jt(time.Hour), lease)
		mustNoErr(t, err)
		mustEqual(t, j.ID, "job_old")
	})

	t.Run("List", func(t *testing.T) {
		s := open(t, newStore)
		for i := range 5 {
			j := pendingJob("ten_a", fmt.Sprintf("job_%d", i), store.JobUsersImport, time.Duration(i)*time.Second)
			j.Input = []byte("input")
			mustNoErr(t, s.Jobs().Create(ctx, j))
		}
		// Same CreatedAt as job_4: the ID breaks the tie, descending.
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_a", "job_9", store.JobUsersExport, 4*time.Second)))
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_b", "job_other", store.JobUsersImport, 0)))

		ids := func(js []*store.Job) []string {
			out := []string{}
			for _, j := range js {
				out = append(out, j.ID)
			}
			return out
		}
		all, total, err := s.Jobs().List(ctx, "ten_a", store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 6)
		mustEqual(t, ids(all), []string{"job_9", "job_4", "job_3", "job_2", "job_1", "job_0"})
		mustEqual(t, all[1].Params, map[string]any{"k": "v"})
		mustEqual(t, all[1].Type, store.JobUsersImport)
		if len(all[1].Input) != 0 {
			t.Errorf("List loaded Input: %q", all[1].Input)
		}
		page, total, err := s.Jobs().List(ctx, "ten_a", store.Page{Offset: 2, Limit: 2})
		mustNoErr(t, err)
		mustEqual(t, total, 6)
		mustEqual(t, ids(page), []string{"job_3", "job_2"})
		page, total, err = s.Jobs().List(ctx, "ten_a", store.Page{Offset: 10, Limit: 2})
		mustNoErr(t, err)
		mustEqual(t, total, 6)
		mustEqual(t, len(page), 0)
		none, total, err := s.Jobs().List(ctx, "ten_c", store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 0)
		mustEqual(t, len(none), 0)
	})

	t.Run("CountActive", func(t *testing.T) {
		s := open(t, newStore)
		mk := func(tenant, id string, typ store.JobType, st store.JobStatus) {
			j := pendingJob(tenant, id, typ, 0)
			j.Status = st
			mustNoErr(t, s.Jobs().Create(ctx, j))
		}
		mk("ten_a", "1", store.JobUsersImport, store.JobPending)
		mk("ten_a", "2", store.JobUsersImport, store.JobProcessing)
		mk("ten_a", "3", store.JobUsersImport, store.JobCompleted)
		mk("ten_a", "4", store.JobUsersImport, store.JobFailed)
		mk("ten_a", "5", store.JobUsersExport, store.JobPending)
		mk("ten_b", "6", store.JobUsersImport, store.JobPending)
		for _, c := range []struct {
			tenant string
			typ    store.JobType
			want   int
		}{
			{"ten_a", store.JobUsersImport, 2}, {"ten_a", store.JobUsersExport, 1},
			{"ten_a", store.JobVerificationEmail, 0}, {"ten_b", store.JobUsersImport, 1}, {"ten_c", store.JobUsersImport, 0},
		} {
			n, err := s.Jobs().CountActive(ctx, c.tenant, c.typ)
			mustNoErr(t, err)
			mustEqual(t, n, c.want)
		}
	})

	t.Run("ClaimOrderAndFields", func(t *testing.T) {
		s := open(t, newStore)
		_, err := s.Jobs().Claim(ctx, "w1", jt(0), lease)
		mustErrIs(t, err, store.ErrNotFound)
		mustNoErr(t, s.Jobs().Create(ctx, pendingJob("ten_b", "job_b", store.JobUsersExport, time.Second)))
		in := pendingJob("ten_a", "job_a", store.JobUsersImport, 0)
		in.Input = []byte("file")
		mustNoErr(t, s.Jobs().Create(ctx, in))
		done := pendingJob("ten_a", "job_done", store.JobUsersImport, -time.Hour)
		done.Status = store.JobCompleted
		mustNoErr(t, s.Jobs().Create(ctx, done))

		now := jt(time.Hour)
		j, err := s.Jobs().Claim(ctx, "w1", now, lease)
		mustNoErr(t, err)
		mustEqual(t, j.TenantID+"/"+j.ID, "ten_a/job_a") // oldest, across tenants
		mustEqual(t, j.Status, store.JobProcessing)
		mustEqual(t, j.LeaseOwner, "w1")
		mustEqual(t, j.LeaseUntil, now.Add(lease))
		mustEqual(t, j.Attempts, 1)
		mustEqual(t, j.FirstClaimedAt, now)
		mustEqual(t, j.UpdatedAt, now)
		mustEqual(t, j.Input, []byte("file"))
		stored, err := s.Jobs().Get(ctx, "ten_a", "job_a")
		mustNoErr(t, err)
		mustEqual(t, stored, j)

		j, err = s.Jobs().Claim(ctx, "w2", now, lease)
		mustNoErr(t, err)
		mustEqual(t, j.TenantID+"/"+j.ID, "ten_b/job_b")
		_, err = s.Jobs().Claim(ctx, "w3", now, lease)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("ClaimRace", func(t *testing.T) {
		s := open(t, newStore)
		const jobs = 5
		for i := range jobs {
			tenant := "ten_a"
			if i%2 == 1 {
				tenant = "ten_b"
			}
			mustNoErr(t, s.Jobs().Create(ctx, pendingJob(tenant, fmt.Sprintf("job_%d", i), store.JobUsersImport, time.Duration(i)*time.Second)))
		}
		got := make([]*store.Job, 20)
		errs := parallel(20, func(i int) error {
			j, err := s.Jobs().Claim(ctx, fmt.Sprintf("w%d", i), jt(time.Hour), lease)
			got[i] = j
			return err
		})
		seen := map[string]bool{}
		for i, err := range errs {
			switch {
			case err == nil:
				k := got[i].TenantID + "/" + got[i].ID
				if seen[k] {
					t.Errorf("job %s claimed twice", k)
				}
				seen[k] = true
				mustEqual(t, got[i].Attempts, 1)
				mustEqual(t, got[i].LeaseOwner, fmt.Sprintf("w%d", i))
			case errors.Is(err, store.ErrNotFound):
			default:
				t.Errorf("claim %d: %v", i, err)
			}
		}
		mustEqual(t, len(seen), jobs)
	})

	t.Run("ClaimStaleLease", func(t *testing.T) {
		s := open(t, newStore)
		first := claimed(t, s, "job_1", "w1", jt(0))
		mustEqual(t, first.Attempts, 1)
		// The lease is live until jt(1m): not claimable.
		_, err := s.Jobs().Claim(ctx, "w2", jt(30*time.Second), lease)
		mustErrIs(t, err, store.ErrNotFound)
		_, err = s.Jobs().Claim(ctx, "w2", jt(time.Minute), lease)
		mustErrIs(t, err, store.ErrNotFound) // LeaseUntil < now, strictly

		again, err := s.Jobs().Claim(ctx, "w2", jt(2*time.Minute), lease)
		mustNoErr(t, err)
		mustEqual(t, again.ID, "job_1")
		mustEqual(t, again.Attempts, 2)
		mustEqual(t, again.LeaseOwner, "w2")
		mustEqual(t, again.LeaseUntil, jt(3*time.Minute))
		mustEqual(t, again.FirstClaimedAt, jt(0)) // kept
		mustEqual(t, again.Status, store.JobProcessing)

		// A second lost lease is not reclaimed; the sweep fails the job.
		_, err = s.Jobs().Claim(ctx, "w3", jt(10*time.Minute), lease)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("LeaseChecks", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		_, err := s.Jobs().Claim(ctx, "w2", jt(2*time.Minute), lease) // w1 lost the lease
		mustNoErr(t, err)

		stale := func(name string, err error) {
			t.Helper()
			if !errors.Is(err, store.ErrConflict) {
				t.Errorf("%s by the old owner: err = %v, want ErrConflict", name, err)
			}
		}
		stale("Renew", s.Jobs().Renew(ctx, "ten_a", "job_1", "w1", jt(time.Hour)))
		stale("Checkpoint", s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 5, store.JobSummary{Total: 5}, []store.JobError{jobErr(0)}))
		stale("AppendFile", s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 0, []byte("x")))
		stale("Finish", s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobCompleted, "", jt(time.Hour)))
		stale("Renew in another tenant", s.Jobs().Renew(ctx, "ten_b", "job_1", "w2", jt(time.Hour)))
		stale("Renew of an unknown job", s.Jobs().Renew(ctx, "ten_a", "nope", "w2", jt(time.Hour)))

		// None of the refused calls changed anything.
		j, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.Status, store.JobProcessing)
		mustEqual(t, j.Progress, 0)
		mustEqual(t, j.FileSize, int64(0))
		mustEqual(t, j.LeaseUntil, jt(3*time.Minute))
		errs, err := s.Jobs().Errors(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(errs), 0)
	})

	t.Run("Renew", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		mustNoErr(t, s.Jobs().Renew(ctx, "ten_a", "job_1", "w1", jt(10*time.Minute)))
		j, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.LeaseUntil, jt(10*time.Minute))
		// The renewed lease keeps others out.
		_, err = s.Jobs().Claim(ctx, "w2", jt(5*time.Minute), lease)
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("CheckpointAndErrors", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		sum := store.JobSummary{Failed: 2, Updated: 1, Inserted: 3, Total: 6}
		mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 6, sum, []store.JobError{jobErr(5), jobErr(3)}))
		mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 7, store.JobSummary{Failed: 3, Updated: 1, Inserted: 3, Total: 7}, []store.JobError{jobErr(4)}))
		mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 8, store.JobSummary{Failed: 3, Updated: 1, Inserted: 4, Total: 8}, nil))
		j, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.Progress, 8)
		mustEqual(t, j.Summary, store.JobSummary{Failed: 3, Updated: 1, Inserted: 4, Total: 8})

		errs, err := s.Jobs().Errors(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, errs, []store.JobError{jobErr(3), jobErr(4), jobErr(5)})

		// A record that is not an object (J2) is kept as the value it was.
		raw := []store.JobError{
			{Index: 10, User: float64(1), Errors: []store.JobErrorItem{{Code: "INVALID_TYPE", Message: "Expected type object but found type integer"}}},
			{Index: 11, User: "x", Errors: []store.JobErrorItem{{Code: "INVALID_TYPE", Message: "Expected type object but found type string"}}},
			{Index: 12, User: nil, Errors: []store.JobErrorItem{{Code: "INVALID_TYPE", Message: "Expected type object but found type null"}}},
		}
		claimed(t, s, "job_2", "w1", jt(0))
		mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_2", "w1", 13, store.JobSummary{Failed: 3, Total: 13}, raw))
		errs, err = s.Jobs().Errors(ctx, "ten_a", "job_2")
		mustNoErr(t, err)
		mustEqual(t, errs, raw)

		// A repeated index is refused and changes nothing.
		mustErrIs(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 9, store.JobSummary{Total: 9}, []store.JobError{jobErr(4)}), store.ErrConflict)
		j, _ = s.Jobs().Get(ctx, "ten_a", "job_1")
		mustEqual(t, j.Progress, 8)

		_, err = s.Jobs().Errors(ctx, "ten_b", "job_1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("CheckpointRollsBackWithItsTransaction", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		mustNoErr(t, s.Users().Create(ctx, newUser("ten_a", "u1", "alice@example.test", "alice")))

		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			u, err := tx.Users().GetForUpdate(ctx, "ten_a", "auth0|u1")
			if err != nil {
				return err
			}
			u.Name = "changed"
			if err := tx.Users().Update(ctx, u); err != nil {
				return err
			}
			if err := tx.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 4, store.JobSummary{Total: 4}, []store.JobError{jobErr(1)}); err != nil {
				return err
			}
			return boom
		})
		mustErrIs(t, err, boom)
		j, _ := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustEqual(t, j.Progress, 0)
		mustEqual(t, j.Summary, store.JobSummary{})
		errs, err := s.Jobs().Errors(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(errs), 0)
		u, _ := s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, u.Name, "User u1")

		// The same transaction, committed, keeps both.
		mustNoErr(t, s.WithTx(ctx, func(tx store.Store) error {
			u, err := tx.Users().GetForUpdate(ctx, "ten_a", "auth0|u1")
			if err != nil {
				return err
			}
			u.Name = "changed"
			if err := tx.Users().Update(ctx, u); err != nil {
				return err
			}
			return tx.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 4, store.JobSummary{Total: 4}, []store.JobError{jobErr(1)})
		}))
		j, _ = s.Jobs().Get(ctx, "ten_a", "job_1")
		mustEqual(t, j.Progress, 4)
		errs, _ = s.Jobs().Errors(ctx, "ten_a", "job_1")
		mustEqual(t, errs, []store.JobError{jobErr(1)})
		u, _ = s.Users().Get(ctx, "ten_a", "auth0|u1")
		mustEqual(t, u.Name, "changed")
	})

	t.Run("CreateInTransaction", func(t *testing.T) {
		s := open(t, newStore)
		boom := errors.New("boom")
		err := s.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Jobs().Create(ctx, pendingJob("ten_a", "job_1", store.JobUsersImport, 0)); err != nil {
				return err
			}
			return boom
		})
		mustErrIs(t, err, boom)
		_, err = s.Jobs().Get(ctx, "ten_a", "job_1")
		mustErrIs(t, err, store.ErrNotFound)
	})

	t.Run("Finish", func(t *testing.T) {
		s := open(t, newStore)
		in := pendingJob("ten_a", "job_1", store.JobUsersImport, 0)
		in.Input = []byte("file")
		mustNoErr(t, s.Jobs().Create(ctx, in))
		_, err := s.Jobs().Claim(ctx, "w1", jt(0), lease)
		mustNoErr(t, err)
		mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", "job_1", "w1", 3, store.JobSummary{Total: 3, Inserted: 3}, nil))

		mustNoErr(t, s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobFailed, "it broke", jt(time.Hour)))
		j, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.Status, store.JobFailed)
		mustEqual(t, j.StatusDetails, "it broke")
		mustEqual(t, j.UpdatedAt, jt(time.Hour))
		mustEqual(t, j.LeaseOwner, "")
		mustEqual(t, j.LeaseUntil, time.Time{})
		if len(j.Input) != 0 {
			t.Errorf("Input kept: %q", j.Input)
		}
		mustEqual(t, j.Progress, 3)
		mustEqual(t, j.Summary, store.JobSummary{Total: 3, Inserted: 3})
		mustEqual(t, j.Attempts, 1)
		mustEqual(t, j.FirstClaimedAt, jt(0))

		// The lease is gone: nothing more from w1, and no one reclaims it.
		mustErrIs(t, s.Jobs().Renew(ctx, "ten_a", "job_1", "w1", jt(2*time.Hour)), store.ErrConflict)
		mustErrIs(t, s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobCompleted, "", jt(2*time.Hour)), store.ErrConflict)
		_, err = s.Jobs().Claim(ctx, "w2", jt(10*time.Hour), lease)
		mustErrIs(t, err, store.ErrNotFound)
		n, err := s.Jobs().CountActive(ctx, "ten_a", store.JobUsersImport)
		mustNoErr(t, err)
		mustEqual(t, n, 0)
	})

	t.Run("InvalidArguments", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		for name, err := range map[string]error{
			"negative seq": s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", -1, []byte("x")),
			"big chunk":    s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 0, make([]byte, store.JobMaxChunk+1)),
			"processing":   s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobProcessing, "", jt(time.Hour)),
			"pending":      s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobPending, "", jt(time.Hour)),
		} {
			if err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
		j, err := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.Status, store.JobProcessing)
		mustEqual(t, j.FileSize, int64(0))
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 0, make([]byte, store.JobMaxChunk)))
	})

	t.Run("File", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		read := func(tenant, id string) ([][]byte, error) {
			var out [][]byte
			err := s.Jobs().ReadFile(ctx, tenant, id, func(c []byte) error {
				out = append(out, bytes.Clone(c))
				return nil
			})
			return out, err
		}
		chunks, err := read("ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(chunks), 0)

		big := bytes.Repeat([]byte("z"), 1<<20)
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 0, []byte("first,")))
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 2, big))
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 1, []byte("second,")))
		mustErrIs(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 1, []byte("again")), store.ErrConflict)

		chunks, err = read("ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(chunks), 3)
		mustEqual(t, chunks[0], []byte("first,"))
		mustEqual(t, chunks[1], []byte("second,"))
		if !bytes.Equal(chunks[2], big) {
			t.Errorf("third chunk differs (%d bytes)", len(chunks[2]))
		}

		j, _ := s.Jobs().Get(ctx, "ten_a", "job_1")
		mustEqual(t, j.FileSize, int64(6+7+len(big))) // the refused chunk is not counted

		stop := errors.New("stop")
		calls := 0
		err = s.Jobs().ReadFile(ctx, "ten_a", "job_1", func([]byte) error { calls++; return stop })
		mustErrIs(t, err, stop)
		mustEqual(t, calls, 1)

		// Chunk 0 starts the file anew.
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 0, []byte("restart")))
		chunks, err = read("ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(chunks), 1)
		mustEqual(t, chunks[0], []byte("restart"))
		j, err = s.Jobs().Get(ctx, "ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, j.FileSize, int64(len("restart")))
		mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", "job_1", "w1", 1, []byte("!")))

		_, err = read("ten_a", "nope")
		mustErrIs(t, err, store.ErrNotFound)
		_, err = read("ten_b", "job_1")
		mustErrIs(t, err, store.ErrNotFound)

		// The file stays readable once the job is finished.
		mustNoErr(t, s.Jobs().Finish(ctx, "ten_a", "job_1", "w1", store.JobCompleted, "", jt(time.Hour)))
		chunks, err = read("ten_a", "job_1")
		mustNoErr(t, err)
		mustEqual(t, len(chunks), 2)
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		s := open(t, newStore)
		before := jt(48 * time.Hour)
		mk := func(id string, mod func(j *store.Job)) {
			j := pendingJob("ten_a", id, store.JobUsersImport, 0)
			j.Input = []byte("file")
			j.ExpiresAt = before.Add(24 * time.Hour)
			mod(j)
			mustNoErr(t, s.Jobs().Create(ctx, j))
		}
		processing := func(j *store.Job, attempts int, first, leaseUntil time.Time) {
			j.Status, j.Attempts, j.LeaseOwner = store.JobProcessing, attempts, "w1"
			j.FirstClaimedAt, j.LeaseUntil = first, leaseUntil
		}
		// The expired job still holds a lease, with errors and a file.
		mk("expired", func(j *store.Job) {
			processing(j, 1, jt(0), before.Add(time.Hour))
			j.ExpiresAt = before.Add(-time.Second)
			j.FileSize = 0
		})
		mk("boundary", func(j *store.Job) { j.ExpiresAt = before }) // not before: kept
		mk("live", func(j *store.Job) { processing(j, 1, before.Add(-time.Minute), before.Add(time.Hour)) })
		mk("timedout", func(j *store.Job) { // running for over 2 hours, lease live
			processing(j, 1, before.Add(-store.JobMaxRuntime-time.Second), before.Add(time.Minute))
		})
		mk("runningok", func(j *store.Job) {
			processing(j, 1, before.Add(-store.JobMaxRuntime+time.Minute), before.Add(time.Minute))
		})
		mk("lostonce", func(j *store.Job) { // one more chance
			processing(j, 1, before.Add(-time.Hour), before.Add(-time.Minute))
		})
		mk("lostTwice", func(j *store.Job) {
			processing(j, 2, before.Add(-time.Hour), before.Add(-time.Minute))
		})
		mk("secondRunning", func(j *store.Job) { // second attempt still holds its lease
			processing(j, 2, before.Add(-time.Hour), before.Add(time.Minute))
		})
		mk("finished", func(j *store.Job) {
			j.Status = store.JobCompleted
			j.FirstClaimedAt = before.Add(-24 * time.Hour) // long ago, but done
			j.Input = nil
		})
		mk("pending", func(j *store.Job) { j.CreatedAt = before.Add(-72 * time.Hour) })

		for _, id := range []string{"expired", "live"} {
			mustNoErr(t, s.Jobs().Checkpoint(ctx, "ten_a", id, "w1", 1, store.JobSummary{Total: 1, Failed: 1}, []store.JobError{jobErr(0)}))
			mustNoErr(t, s.Jobs().AppendFile(ctx, "ten_a", id, "w1", 0, []byte("chunk")))
		}

		n, err := s.Jobs().DeleteExpired(ctx, before)
		mustNoErr(t, err)
		mustEqual(t, n, 1)
		_, err = s.Jobs().Get(ctx, "ten_a", "expired")
		mustErrIs(t, err, store.ErrNotFound)
		// Its errors and chunks went with it: a job made again under the
		// same ID starts empty.
		again := pendingJob("ten_a", "expired", store.JobUsersImport, 0)
		again.ExpiresAt = before.Add(24 * time.Hour)
		mustNoErr(t, s.Jobs().Create(ctx, again))
		errs, err := s.Jobs().Errors(ctx, "ten_a", "expired")
		mustNoErr(t, err)
		mustEqual(t, len(errs), 0)
		calls := 0
		mustNoErr(t, s.Jobs().ReadFile(ctx, "ten_a", "expired", func([]byte) error { calls++; return nil }))
		mustEqual(t, calls, 0)
		// The live job's are still there.
		errs, err = s.Jobs().Errors(ctx, "ten_a", "live")
		mustNoErr(t, err)
		mustEqual(t, errs, []store.JobError{jobErr(0)})

		status := func(id string) *store.Job {
			t.Helper()
			j, err := s.Jobs().Get(ctx, "ten_a", id)
			mustNoErr(t, err)
			return j
		}
		for _, c := range []struct {
			id      string
			status  store.JobStatus
			details string
		}{
			{"timedout", store.JobFailed, store.JobDetailTimedOut},
			{"lostTwice", store.JobFailed, store.JobDetailWorkerLost},
			{"boundary", store.JobPending, ""},
			{"live", store.JobProcessing, ""},
			{"runningok", store.JobProcessing, ""},
			{"lostonce", store.JobProcessing, ""},
			{"secondRunning", store.JobProcessing, ""},
			{"finished", store.JobCompleted, ""},
			{"pending", store.JobPending, ""},
		} {
			j := status(c.id)
			mustEqual(t, j.Status, c.status)
			mustEqual(t, j.StatusDetails, c.details)
			if c.status == store.JobFailed {
				mustEqual(t, j.LeaseOwner, "")
				mustEqual(t, j.LeaseUntil, time.Time{})
				mustEqual(t, j.UpdatedAt, before)
				if len(j.Input) != 0 {
					t.Errorf("%s: Input kept", c.id)
				}
			}
		}
		// The failed jobs are no longer active; the one with a second chance
		// is still claimable.
		active, err := s.Jobs().CountActive(ctx, "ten_a", store.JobUsersImport)
		mustNoErr(t, err)
		mustEqual(t, active, 7) // boundary, live, runningok, lostonce, secondRunning, pending, expired(again)
		claimedIDs := map[string]int{}
		for {
			c, err := s.Jobs().Claim(ctx, "w2", before, lease)
			if errors.Is(err, store.ErrNotFound) {
				break
			}
			mustNoErr(t, err)
			claimedIDs[c.ID] = c.Attempts
		}
		mustEqual(t, claimedIDs, map[string]int{"boundary": 1, "pending": 1, "expired": 1, "lostonce": 2})

		n, err = s.Jobs().DeleteExpired(ctx, before)
		mustNoErr(t, err)
		mustEqual(t, n, 0)
	})

	t.Run("TenantIsolation", func(t *testing.T) {
		s := open(t, newStore)
		claimed(t, s, "job_1", "w1", jt(0))
		mustErrIs(t, s.Jobs().Renew(ctx, "ten_b", "job_1", "w1", jt(time.Hour)), store.ErrConflict)
		mustErrIs(t, s.Jobs().Checkpoint(ctx, "ten_b", "job_1", "w1", 1, store.JobSummary{}, nil), store.ErrConflict)
		mustErrIs(t, s.Jobs().AppendFile(ctx, "ten_b", "job_1", "w1", 0, []byte("x")), store.ErrConflict)
		mustErrIs(t, s.Jobs().Finish(ctx, "ten_b", "job_1", "w1", store.JobCompleted, "", jt(0)), store.ErrConflict)
		list, total, err := s.Jobs().List(ctx, "ten_b", store.Page{})
		mustNoErr(t, err)
		mustEqual(t, total, 0)
		mustEqual(t, len(list), 0)
	})
}
