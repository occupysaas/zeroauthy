package grpcstore

import (
	"context"
	"errors"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/store/memory"
	"github.com/zeroauthy/zeroauthy/pkg/storetest"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"sort"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func TestMFACapabilities(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	supporter, ok := any(c).(interface {
		CheckMFASupport(context.Context) error
		MFASupported() bool
	})
	if !ok {
		t.Fatal("MFA capability missing")
	}
	if err := supporter.CheckMFASupport(context.Background()); err != nil || !supporter.MFASupported() {
		t.Fatalf("MFA support: %v", err)
	}
}

func TestMFARemoteConditionalUpdates(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx := context.Background()
	if err := c.Tenants().Create(ctx, &store.Tenant{ID: "mfa", Name: "mfa"}); err != nil {
		t.Fatal(err)
	}
	if err := c.Users().Create(ctx, &store.User{TenantID: "mfa", UserID: "u"}); err != nil {
		t.Fatal(err)
	}
	a := &store.Authenticator{TenantID: "mfa", UserID: "u", ID: "a", Type: "totp"}
	if err := c.MFA().CreateAuthenticator(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().AcceptTOTPStep(ctx, "mfa", "u", "a", 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().AcceptTOTPStep(ctx, "mfa", "u", "a", 1, time.Now()); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("replay: %v", err)
	}

	now := time.Now()
	if err := c.MFA().AcceptSignCount(ctx, "mfa", "u", "a", 3, now); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().AcceptSignCount(ctx, "mfa", "u", "a", 3, now); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("sign count replay: %v", err)
	}
	if err := c.MFA().ReplaceRecoveryCode(ctx, "mfa", "u", "", "first", now); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().ReplaceRecoveryCode(ctx, "mfa", "u", "first", "second", now); err != nil {
		t.Fatal(err)
	}
	if err := c.MFA().ReplaceRecoveryCode(ctx, "mfa", "u", "first", "third", now); !errors.Is(err, store.ErrPrecondition) {
		t.Fatalf("recovery replay: %v", err)
	}
	if err := c.MFA().DeleteUserAuthenticators(ctx, "mfa", "u", []string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MFA().GetAuthenticator(ctx, "mfa", "u", "a"); err != nil {
		t.Fatalf("empty type filter deleted factor: %v", err)
	}
}

func TestMFACapabilityCompatibility(t *testing.T) {
	ctx := context.Background()
	t.Run("old-plugin", func(t *testing.T) {
		c := serveEventsFaults(t, memory.New(), &eventsFaults{mfaMissing: true})
		if c.MFASupported() {
			t.Fatal("old plugin reports MFA support")
		}
		if _, err := c.MFA().GetGuardian(ctx, "t"); !errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("old plugin: %v", err)
		}
		if err := c.WithTx(ctx, func(tx store.Store) error {
			if tx.(store.MFASupporter).MFASupported() {
				t.Fatal("transaction reports MFA support")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("transient", func(t *testing.T) {
		f := &eventsFaults{}
		c := serveEventsFaults(t, memory.New(), f)
		f.mfaProbe.Store(int32(codes.Unavailable))
		if c.MFASupported() {
			t.Fatal("failed probe reported support")
		}
		if !c.MFASupported() {
			t.Fatal("transient probe was cached")
		}
		f.mfaOperation.Store(int32(codes.Unavailable))
		if _, err := c.MFA().GetGuardian(ctx, "t"); err == nil || errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("transport error: %v", err)
		}
		f.mfaOperation.Store(int32(codes.Unimplemented))
		if _, err := c.MFA().GetGuardian(ctx, "t"); !errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("unknown method: %v", err)
		}
		if c.MFASupported() {
			t.Fatal("unknown method not cached")
		}
		if err := c.CheckMFASupport(ctx); !errors.Is(err, store.ErrMFAUnavailable) {
			t.Fatalf("latched: %v", err)
		}
	})
}
func TestMFAPrePluginPriorFeatures(t *testing.T) {
	var names []string
	for n := range storetest.Suites {
		// WebAuthn credentials are MFA authenticator rows, so a plugin
		// without MFA storage cannot hold them either.
		if n != "MFA" && n != "WebAuthn" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	storetest.RunSuites(t, func(t *testing.T) store.Store {
		m := memory.New()
		c := serveEventsFaults(t, m, &eventsFaults{mfaMissing: true})
		if !errors.Is(c.CheckMFASupport(context.Background()), store.ErrMFAUnavailable) {
			t.Fatal("MFA advertised")
		}
		return limitForwarder{c, m}
	}, names...)
}

func TestMFAMalformedWrites(t *testing.T) {
	s := NewServer(memory.New())
	defer s.Close()
	ctx := context.Background()
	t.Run("PutGuardian", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFAPutGuardian(ctx, &storev1.MFAPutGuardianRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("CreateAuthenticator", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFACreateAuthenticator(ctx, &storev1.MFACreateAuthenticatorRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("UpdateAuthenticator", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFAUpdateAuthenticator(ctx, &storev1.MFAUpdateAuthenticatorRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("CreateMFAToken", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFACreateMFAToken(ctx, &storev1.MFACreateMFATokenRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("CreateChallenge", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFACreateChallenge(ctx, &storev1.MFACreateChallengeRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("CreateTicket", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFACreateTicket(ctx, &storev1.MFACreateTicketRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
	t.Run("PutBrowser", func(t *testing.T) {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
			}
		}()
		r, err := s.MFAPutBrowser(ctx, &storev1.MFAPutBrowserRequest{})
		if err != nil || !errors.Is(errFromPB(r.GetError()), store.ErrInvalid) {
			t.Fatalf("result=%v error=%v", r, err)
		}
	})
}
func TestMFAUnsupportedStaysLatched(t *testing.T) {
	ctx := context.Background()
	f := &eventsFaults{}
	c := serveEventsFaults(t, memory.New(), f)
	f.mfaOperation.Store(int32(codes.Unimplemented))
	if _, err := c.MFA().GetGuardian(ctx, "t"); !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatal(err)
	}
	if err := c.CheckMFASupport(ctx); !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatalf("probe cleared unsupported: %v", err)
	}
	if c.MFASupported() {
		t.Fatal("unsupported capability reset")
	}
}
func TestMFAMarkUnknownMethodLatched(t *testing.T) {
	ctx := context.Background()
	f := &eventsFaults{}
	c := serveEventsFaults(t, memory.New(), f)
	f.mfaMark.Store(int32(codes.Unimplemented))
	if err := c.Sessions().MarkMFA(ctx, "t", "s", time.Now()); !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatal(err)
	}
	if err := c.CheckMFASupport(ctx); !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatalf("probe cleared mark failure: %v", err)
	}
}

func TestMFAConcurrentProbeCannotClearUnsupported(t *testing.T) {
	ctx := context.Background()
	f := &eventsFaults{mfaProbeEntered: make(chan struct{}, 1), mfaProbeRelease: make(chan struct{})}
	c := serveEventsFaults(t, memory.New(), f)
	f.mfaBlock.Store(true)
	result := make(chan error, 1)
	go func() { result <- c.CheckMFASupport(ctx) }()
	<-f.mfaProbeEntered
	f.mfaMark.Store(int32(codes.Unimplemented))
	if err := c.Sessions().MarkMFA(ctx, "t", "s", time.Now()); !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatal(err)
	}
	close(f.mfaProbeRelease)
	if err := <-result; !errors.Is(err, store.ErrMFAUnavailable) {
		t.Fatalf("concurrent probe: %v", err)
	}
	if c.MFASupported() {
		t.Fatal("concurrent probe cleared latch")
	}
}

func TestMFADomainUnavailableLatches(t *testing.T) {
	for _, mark := range []bool{false, true} {
		t.Run(fmt.Sprint(mark), func(t *testing.T) {
			ctx := context.Background()
			f := &eventsFaults{mfaProbeEntered: make(chan struct{}, 1), mfaProbeRelease: make(chan struct{})}
			c := serveEventsFaults(t, memory.New(), f)
			f.mfaBlock.Store(true)
			result := make(chan error, 1)
			go func() { result <- c.CheckMFASupport(ctx) }()
			<-f.mfaProbeEntered
			var err error
			if mark {
				f.mfaDomainMark.Store(true)
				err = c.Sessions().MarkMFA(ctx, "t", "s", time.Now())
			} else {
				f.mfaDomainOperation.Store(true)
				_, err = c.MFA().GetGuardian(ctx, "t")
			}
			if !errors.Is(err, store.ErrMFAUnavailable) {
				t.Fatalf("operation: %v", err)
			}
			close(f.mfaProbeRelease)
			if err = <-result; !errors.Is(err, store.ErrMFAUnavailable) {
				t.Fatalf("concurrent probe cleared latch: %v", err)
			}
			if c.MFASupported() {
				t.Fatal("domain error not latched")
			}
			if err = c.CheckMFASupport(ctx); !errors.Is(err, store.ErrMFAUnavailable) {
				t.Fatalf("subsequent probe: %v", err)
			}
		})
	}
}
func TestMFAConversionRejectsUnmatchedFields(t *testing.T) {
	type source struct {
		TenantID      string
		SecurityField string
	}
	type destination struct{ TenantID string }
	var d destination
	if err := copyMFA(&d, source{TenantID: "t", SecurityField: "secret"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unmatched source: %v", err)
	}
	var s source
	if err := copyMFA(&s, destination{TenantID: "t"}); !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("unmatched destination: %v", err)
	}
}
