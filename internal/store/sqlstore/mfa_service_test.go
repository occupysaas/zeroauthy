package sqlstore

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	mfasvc "github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Schedule the unsafe predicate reads, without requiring two readers to pass a
// real user lock. With locking, the database itself serializes the requests.
// Without locking, both restricted readers see the empty predicate and actor 1
// returns its stale snapshot after actor 0 commits. The mixed case lets the
// ordinary enrollment commit after the restricted reader's stale snapshot.
// These wrappers change scheduling only; all reads/writes/proofs use real SQL.
type enrollmentRace struct {
	ordinary, coordinate bool
	started, committed   chan struct{}
	predicates           [2]chan struct{}
	startOnce            sync.Once
}
type enrollmentRaceStore struct {
	store.Store
	race                        *enrollmentRace
	actor                       int
	inTx, locked, readPredicate bool
}

func (s *enrollmentRaceStore) WithTx(ctx context.Context, fn func(store.Store) error) error {
	err := s.Store.WithTx(ctx, func(tx store.Store) error {
		return fn(&enrollmentRaceStore{Store: tx, race: s.race, actor: s.actor, inTx: true})
	})
	if s.actor == 0 {
		close(s.race.committed)
	}
	return err
}
func (s *enrollmentRaceStore) Users() store.Users {
	return enrollmentRaceUsers{Users: s.Store.Users(), s: s}
}

type enrollmentRaceUsers struct {
	store.Users
	s *enrollmentRaceStore
}

func (r enrollmentRaceUsers) GetForUpdate(ctx context.Context, tid, uid string) (*store.User, error) {
	u, err := r.Users.GetForUpdate(ctx, tid, uid)
	if err == nil {
		r.s.locked = true
		if r.s.race.ordinary && r.s.actor == 0 {
			r.s.race.startOnce.Do(func() { close(r.s.race.started) })
		}
	}
	return u, err
}
func (s *enrollmentRaceStore) MFA() store.MFA { return enrollmentRaceMFA{MFA: s.Store.MFA(), s: s} }

type enrollmentRaceMFA struct {
	store.MFA
	s *enrollmentRaceStore
}

func (r enrollmentRaceMFA) GetAuthenticator(ctx context.Context, tid, uid, id string) (*store.Authenticator, error) {
	if r.s.inTx && r.s.race.ordinary && r.s.actor == 0 {
		r.s.race.startOnce.Do(func() { close(r.s.race.started) })
		if r.s.race.coordinate && !r.s.locked {
			select {
			case <-r.s.race.predicates[1]:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return r.MFA.GetAuthenticator(ctx, tid, uid, id)
}
func (r enrollmentRaceMFA) ListAuthenticators(ctx context.Context, tid, uid string) ([]store.Authenticator, error) {
	list, err := r.MFA.ListAuthenticators(ctx, tid, uid)
	if err != nil || !r.s.inTx || r.s.locked || !r.s.race.coordinate || r.s.readPredicate || r.s.race.ordinary && r.s.actor == 0 {
		return list, err
	}
	r.s.readPredicate = true
	close(r.s.race.predicates[r.s.actor])
	if !r.s.race.ordinary {
		select {
		case <-r.s.race.predicates[1-r.s.actor]:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.s.actor == 1 {
		select {
		case <-r.s.race.committed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return list, nil
}
func enrollmentCode(secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(counter[:])
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}

func TestMFAServiceEnrollmentUserSerialization(t *testing.T) {
	for dialect, mk := range dsnsUnderTest(t) {
		t.Run(dialect, func(t *testing.T) {
			for _, ordinary := range []bool{false, true} {
				name := "restricted_tickets"
				if ordinary {
					name = "ordinary_before_restricted_ticket"
				}
				t.Run(name, func(t *testing.T) {
					dsn := mk(t)
					a := mustOpen(t, dsn)
					b := mustOpenRaw(t, dsn)
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					mustEvent(t, a.Tenants().Create(ctx, &store.Tenant{ID: "tenant", Name: "tenant"}))
					mustEvent(t, a.Users().Create(ctx, &store.User{TenantID: "tenant", UserID: "user", Email: "user@example.test", EmailVerified: true}))
					g, err := a.MFA().GetGuardian(ctx, "tenant")
					mustEvent(t, err)
					g.Factors = map[string]bool{"otp": true, "recovery-code": true}
					mustEvent(t, a.MFA().PutGuardian(ctx, g, g.Version))
					wrapper, err := keys.NewLocalWrapper(make([]byte, 32))
					mustEvent(t, err)
					now := time.Unix(1800000000, 0).UTC()
					clock := func() time.Time { return now }
					setup := mfasvc.NewService(a, wrapper, nil, nil, nil, clock)
					first, err := setup.BeginEnroll(ctx, "tenant", "user", "otp", "tenant.test")
					mustEvent(t, err)
					second, err := setup.BeginEnroll(ctx, "tenant", "user", "otp", "tenant.test")
					mustEvent(t, err)
					race := &enrollmentRace{ordinary: ordinary, coordinate: dialect != "sqlite", started: make(chan struct{}), committed: make(chan struct{}), predicates: [2]chan struct{}{make(chan struct{}), make(chan struct{})}}
					services := []*mfasvc.Service{mfasvc.NewService(&enrollmentRaceStore{Store: a, race: race, actor: 0}, wrapper, nil, nil, nil, clock), mfasvc.NewService(&enrollmentRaceStore{Store: b, race: race, actor: 1}, wrapper, nil, nil, nil, clock)}
					enrollments := []*mfasvc.Enrollment{first, second}
					errs := make([]error, 2)
					var wg sync.WaitGroup
					for i := range 2 {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							if ordinary && i == 1 {
								select {
								case <-race.started:
								case <-ctx.Done():
									errs[i] = ctx.Err()
									return
								}
							}
							confirm := services[i].ConfirmFirstEnroll
							if ordinary && i == 0 {
								confirm = services[i].ConfirmEnroll
							}
							_, errs[i] = confirm(ctx, "tenant", "user", enrollments[i], mfasvc.Proof{Code: enrollmentCode(enrollments[i].Secret, now)})
						}(i)
					}
					wg.Wait()
					wins := 0
					for _, err := range errs {
						if err == nil {
							wins++
						} else if !errors.Is(err, mfasvc.ErrInvalidCode) {
							t.Fatalf("unexpected enrollment error: %v (all: %v)", err, errs)
						}
					}
					if wins != 1 {
						t.Fatalf("restricted enrollment race allowed %d successes: %v", wins, errs)
					}
					methods, err := a.MFA().ListAuthenticators(ctx, "tenant", "user")
					mustEvent(t, err)
					confirmed := 0
					for _, v := range methods {
						if v.Confirmed && v.Type == "totp" {
							confirmed++
						}
					}
					if confirmed != 1 {
						t.Fatalf("confirmed primary methods=%d", confirmed)
					}
					// The same loser remains usable with ordinary allow-multiple confirmation.
					loser := 0
					if errs[1] != nil {
						loser = 1
					}
					allow := mfasvc.NewService(b, wrapper, nil, nil, nil, clock)
					_, err = allow.ConfirmEnroll(ctx, "tenant", "user", enrollments[loser], mfasvc.Proof{Code: enrollmentCode(enrollments[loser].Secret, now)})
					mustEvent(t, err)
					methods, err = a.MFA().ListAuthenticators(ctx, "tenant", "user")
					mustEvent(t, err)
					confirmed = 0
					for _, v := range methods {
						if v.Confirmed && v.Type == "totp" {
							confirmed++
						}
					}
					if confirmed != 2 {
						t.Fatalf("allow-multiple primary methods=%d", confirmed)
					}
				})
			}
		})
	}
}
