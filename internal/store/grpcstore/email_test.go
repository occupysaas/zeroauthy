package grpcstore

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestEmailGRPCRollback(t *testing.T) {
	ctx := context.Background()
	st := inProcessSQLite(t)
	defer st.Close()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "email-tx", Name: "email-tx"}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("abort email transaction")
	err := st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.EmailProviders().Put(ctx, &store.EmailProvider{TenantID: "email-tx", Name: "sendgrid", SealedCredentials: []byte{1, 2, 3}}, 0); err != nil {
			return err
		}
		if err := tx.EmailTemplates().Put(ctx, &store.EmailTemplate{TenantID: "email-tx", Name: "welcome_email", Fields: map[string]any{"subject": "Hello"}}, 0); err != nil {
			return err
		}
		if ok, err := tx.EmailNotifications().Claim(ctx, "email-tx", "user-1", "welcome", "", time.Now(), time.Time{}, 1); err != nil || !ok {
			return errors.New("claim was not accepted")
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("transaction error=%v", err)
	}
	if _, err = st.EmailProviders().Get(ctx, "email-tx"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("provider after rollback=%v", err)
	}
	if _, err = st.EmailTemplates().Get(ctx, "email-tx", "welcome_email"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("template after rollback=%v", err)
	}
	if ok, err := st.EmailNotifications().Claim(ctx, "email-tx", "user-1", "welcome", "", time.Now(), time.Time{}, 1); err != nil || !ok {
		t.Fatalf("claim after rollback=%v,%v", ok, err)
	}
}

func TestEmailGRPCClaims(t *testing.T) {
	ctx := context.Background()
	st := inProcessSQLite(t)
	defer st.Close()
	if err := st.Tenants().Create(ctx, &store.Tenant{ID: "email-claims", Name: "email-claims"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	for i := 0; i < 2; i++ {
		ok, err := st.EmailNotifications().Claim(ctx, "email-claims", "operator", "test", "window", now, expires, 2)
		if err != nil || !ok {
			t.Fatalf("claim %d=%v,%v", i, ok, err)
		}
	}
	if ok, err := st.EmailNotifications().Claim(ctx, "email-claims", "operator", "test", "window", now, expires, 2); err != nil || ok {
		t.Fatalf("over limit claim=%v,%v", ok, err)
	}
	if n, err := st.EmailNotifications().Sweep(ctx, expires.Add(-time.Second), 10); err != nil || n != 0 {
		t.Fatalf("early sweep=%d,%v", n, err)
	}
	if n, err := st.EmailNotifications().Sweep(ctx, expires.Add(time.Second), 10); err != nil || n != 1 {
		t.Fatalf("expired sweep=%d,%v", n, err)
	}
	if ok, err := st.EmailNotifications().Claim(ctx, "email-claims", "operator", "preview", "permanent", now, time.Time{}, 1); err != nil || !ok {
		t.Fatalf("permanent claim=%v,%v", ok, err)
	}
	if n, err := st.EmailNotifications().Sweep(ctx, time.Now().Add(24*time.Hour), 10); err != nil || n != 0 {
		t.Fatalf("permanent sweep=%d,%v", n, err)
	}
}

func TestEmailGRPCUnimplemented(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	storev1.RegisterStoreServiceServer(gs, &storev1.UnimplementedStoreServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()
	conn, err := grpc.NewClient("passthrough:///old-plugin", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = NewClient(conn, nil).EmailProviders().Get(context.Background(), "t")
	if status.Code(err) != codes.Unimplemented || errors.Is(err, store.ErrEmailRepositoryUnavailable) {
		t.Fatalf("old plugin error=%v", err)
	}
}

func TestEmailGRPCCodecRoundTrip(t *testing.T) {
	cases := []*store.EmailProvider{{TenantID: "t", Name: "smtp", PublicConfig: nil, SealedCredentials: []byte{0, 1, 255}, Revision: 7}, {TenantID: "t", Name: "mailgun", PublicConfig: map[string]any{}, SealedCredentials: []byte{}, Revision: 8}, {TenantID: "t", Name: "sendgrid", PublicConfig: map[string]any{"nested": map[string]any{"items": []any{"x", float64(2), true, nil}}}, Revision: 9}}
	for _, in := range cases {
		pb, err := emailProviderToPB(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := emailProviderFromPB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if got.TenantID != in.TenantID || got.Name != in.Name || got.Revision != in.Revision || !bytes.Equal(got.SealedCredentials, in.SealedCredentials) || ((in.PublicConfig == nil) != (got.PublicConfig == nil)) {
			t.Fatalf("provider roundtrip: got=%+v want=%+v", got, in)
		}
	}
	for _, in := range []*store.EmailTemplate{{TenantID: "t", Name: "verify_email", Fields: nil}, {TenantID: "t", Name: "welcome_email", Fields: map[string]any{}}, {TenantID: "t", Name: "invite_email", Fields: map[string]any{"subject": "Hi", "nested": []any{nil, "ok"}}}} {
		pb, err := emailTemplateToPB(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := emailTemplateFromPB(pb)
		if err != nil {
			t.Fatal(err)
		}
		if got.Name != in.Name || ((in.Fields == nil) != (got.Fields == nil)) {
			t.Fatalf("template roundtrip: got=%+v want=%+v", got, in)
		}
	}
}

func TestEmailGRPCConcurrentSQLiteClaims(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "grpc-email-concurrent.db")
	sqlst, err := sqlstore.Open(ctx, "sqlite://"+path)
	if err != nil {
		t.Fatal(err)
	}
	if err = sqlst.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	st := serve(t, sqlst)
	defer st.Close()
	if err = st.Tenants().Create(ctx, &store.Tenant{ID: "email-concurrent", Name: "email-concurrent"}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	errs := []error{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := st.EmailNotifications().Claim(ctx, "email-concurrent", "operator", "preview", "window", time.Now(), time.Now().Add(time.Minute), 5)
			mu.Lock()
			defer mu.Unlock()
			if e != nil {
				errs = append(errs, e)
			} else if ok {
				won++
			}
		}()
	}
	wg.Wait()
	if won != 5 || len(errs) > 0 {
		t.Fatalf("claims won=%d errors=%v", won, errs)
	}
}
