package grpcstore

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// A panic inside fn rolls the remote transaction back and is re-raised.
func TestClientWithTxPanicRollsBack(t *testing.T) {
	ctx := context.Background()
	c := inProcess(t)
	defer c.Close()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		_ = c.WithTx(ctx, func(tx store.Store) error {
			if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "p", Name: "p"}); err != nil {
				return err
			}
			panic("boom")
		})
	}()
	if _, err := c.Tenants().Get(ctx, "p"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after panic: %v", err)
	}
	// The server-side transaction was released: another WithTx proceeds.
	if err := c.WithTx(ctx, func(store.Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// Cancelling ctx inside fn still rolls back (Rollback uses WithoutCancel).
func TestClientWithTxCancelledContext(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err := c.WithTx(ctx, func(tx store.Store) error {
		if err := tx.Tenants().Create(ctx, &store.Tenant{ID: "c", Name: "c"}); err != nil {
			return err
		}
		cancel()
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.Tenants().Get(context.Background(), "c"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("write after cancel: %v", err)
	}
}

// Transport failures are errors, not domain errors.
func TestClientTransportErrorIsNotADomainError(t *testing.T) {
	c := inProcess(t)
	c.Close()
	_, err := c.Tenants().Get(context.Background(), "x")
	assertTransportErr(t, err)
	assertTransportErr(t, c.Tenants().Create(context.Background(), &store.Tenant{ID: "x", Name: "x"}))
}

func assertTransportErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error, want a transport error")
	}
	for _, s := range []error{store.ErrNotFound, store.ErrConflict, store.ErrAlreadyUsed} {
		if errors.Is(err, s) {
			t.Fatalf("err = %v matches %v", err, s)
		}
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatalf("err = %v carries no gRPC status", err)
	}
}

// Context errors surface as context errors, keeping the gRPC status.
func TestClientContextErrors(t *testing.T) {
	c := inProcess(t)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := c.Tenants().Create(ctx, &store.Tenant{ID: "x", Name: "x"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
	var se interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &se) {
		t.Fatal("status dropped from chain")
	}
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer dcancel()
	err = c.WithTx(dctx, func(store.Store) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &se) {
		t.Fatalf("deadline: %v", err)
	}
}

// fakeRPC fails Commit and records Rollback.
type fakeRPC struct {
	storev1.StoreServiceClient
	commitErr  error
	commitPB   *storev1.Error
	rolledBack int
}

func (f *fakeRPC) BeginTx(context.Context, *storev1.BeginTxRequest, ...grpc.CallOption) (*storev1.BeginTxResponse, error) {
	return &storev1.BeginTxResponse{TxId: "t"}, nil
}

func (f *fakeRPC) Commit(context.Context, *storev1.EndTxRequest, ...grpc.CallOption) (*storev1.Result, error) {
	return &storev1.Result{Error: f.commitPB}, f.commitErr
}

func (f *fakeRPC) Rollback(context.Context, *storev1.EndTxRequest, ...grpc.CallOption) (*storev1.Result, error) {
	f.rolledBack++
	return &storev1.Result{}, errors.New("rollback failed")
}

// A failed Commit still sends a best-effort Rollback and returns the Commit error.
func TestClientFailedCommitRollsBack(t *testing.T) {
	for name, f := range map[string]*fakeRPC{
		"transport": {commitErr: status.Error(codes.Unavailable, "gone")},
		"domain":    {commitPB: &storev1.Error{Kind: storev1.Error_KIND_CONFLICT, Message: "open nested transaction"}},
	} {
		c := &Client{rpc: f}
		err := c.WithTx(context.Background(), func(store.Store) error { return nil })
		if err == nil || f.rolledBack != 1 {
			t.Fatalf("%s: err = %v, rollbacks = %d", name, err, f.rolledBack)
		}
		if strings.Contains(err.Error(), "rollback failed") {
			t.Fatalf("%s: rollback error leaked: %v", name, err)
		}
	}
}

// fakeFind answers ClientGrantsFind with a fixed grant, as a plugin that
// predates subject_type would.
type fakeFind struct {
	storev1.StoreServiceClient
	got *storev1.ClientGrantsFindRequest
}

func (f *fakeFind) ClientGrantsFind(_ context.Context, r *storev1.ClientGrantsFindRequest, _ ...grpc.CallOption) (*storev1.ClientGrantResult, error) {
	f.got = r
	return &storev1.ClientGrantResult{Value: &storev1.ClientGrant{TenantId: "t", Id: "g", ClientId: "c", Audience: "a",
		SubjectType: "client", CreatedAt: tsToPB(time.Unix(0, 0))}}, nil
}

func TestFindIgnoresWrongSubjectType(t *testing.T) {
	// An old plugin ignores subject_type and returns the client grant.
	f := &fakeFind{}
	c := &Client{rpc: f}
	_, err := c.ClientGrants().Find(context.Background(), "t", "c", "a", store.SubjectTypeUser)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if f.got.GetSubjectType() != store.SubjectTypeUser {
		t.Fatalf("subject_type sent = %q", f.got.GetSubjectType())
	}
	g, err := c.ClientGrants().Find(context.Background(), "t", "c", "a", store.SubjectTypeClient)
	if err != nil || g.SubjectType != store.SubjectTypeClient {
		t.Fatalf("matching type: %+v %v", g, err)
	}
}

// oldPlugin answers every RPC with Unimplemented, like a plugin built before
// the RPC existed.
type oldPlugin struct {
	storev1.UnimplementedStoreServiceServer
}

// listingPlugin is a pre-Plan-15 plugin that can list connections.
type listingPlugin struct{ oldPlugin }

func (listingPlugin) ConnectionsList(context.Context, *storev1.TenantScope) (*storev1.ConnectionList, error) {
	return &storev1.ConnectionList{Values: []*storev1.Connection{{TenantId: "t", Id: "c1", Name: "Db", CreatedAt: tsToPB(time.Unix(0, 0))}}}, nil
}

func serveOldPlugin(t *testing.T) *Client { return serveWith(t, oldPlugin{}) }

func TestOldPluginHostedLoginUnavailable(t *testing.T) {
	c := serveOldPlugin(t)
	defer c.Close()
	ctx := context.Background()
	if _, err := c.HostedLogins().Get(ctx, "tenant"); !errors.Is(err, store.ErrHostedLoginRepositoryUnavailable) {
		t.Fatalf("get error=%v", err)
	}
	if err := c.HostedLogins().Put(ctx, &store.HostedLoginConfig{TenantID: "tenant"}, 0); !errors.Is(err, store.ErrHostedLoginRepositoryUnavailable) {
		t.Fatalf("put error=%v", err)
	}
	if err := c.AuthTransactions().CompareAndSwapHosted(ctx, "tenant", "flow", 0, store.HostedLoginState{}, time.Now()); !errors.Is(err, store.ErrHostedLoginRepositoryUnavailable) {
		t.Fatalf("transition error=%v", err)
	}
}

func serveWith(t *testing.T, srv storev1.StoreServiceServer) *Client {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	storev1.RegisterStoreServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(conn, func() error { err := conn.Close(); gs.Stop(); return err })
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// The sweeper runs on every deployment. A plugin that predates PAR stores no
// pushed requests, so there is nothing to sweep and nothing to report.
func TestOldPluginPushedAuthRequestsSweep(t *testing.T) {
	c := serveOldPlugin(t)
	n, err := c.PushedAuthRequests().DeleteExpired(context.Background(), time.Now())
	if n != 0 || err != nil {
		t.Fatalf("DeleteExpired = %d, %v; want 0, nil", n, err)
	}
	// Other calls still fail: PAR cannot silently work without storage.
	if _, err := c.PushedAuthRequests().Get(context.Background(), "t", "h"); err == nil {
		t.Fatal("Get on an old plugin succeeded")
	}
}

// A plugin that predates device codes stores none, so the sweeper has nothing
// to remove and nothing to report; the other jobs still run.
func TestOldPluginDeviceCodesSweep(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	n, err := c.DeviceCodes().DeleteExpired(ctx, time.Now())
	if n != 0 || err != nil {
		t.Fatalf("DeleteExpired = %d, %v; want 0, nil", n, err)
	}
	if n, err := c.PushedAuthRequests().DeleteExpired(ctx, time.Now()); n != 0 || err != nil {
		t.Fatalf("PAR DeleteExpired = %d, %v; want 0, nil", n, err)
	}
	// Other calls still fail: the device flow cannot silently work without storage.
	if _, err := c.DeviceCodes().Get(ctx, "t", "h"); err == nil {
		t.Fatal("Get on an old plugin succeeded")
	}
}

// Listing resource servers and client grants needs a Plan 14 plugin.
func TestOldPluginListsTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	_, errRS := c.ResourceServers().List(ctx, "t")
	_, _, errCG := c.ClientGrants().List(ctx, "t", store.ClientGrantFilter{}, store.Page{})
	for name, err := range map[string]error{"ResourceServers.List": errRS, "ClientGrants.List": errCG} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want errPluginTooOld", name, err)
		}
	}
}

// The new user-management reads and the verification tickets need a Plan 17
// plugin; the error says so. The sweeper alone treats a missing
// EmailVerificationTicketsDeleteExpired as an empty table.
func TestOldPluginUserManagementTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	_, errSes := c.Sessions().Get(ctx, "t", "s")
	_, errSesList := c.Sessions().ListByUser(ctx, "t", "u")
	_, errRT := c.RefreshTokens().Get(ctx, "t", "r")
	_, errRTList := c.RefreshTokens().ListByUser(ctx, "t", "u")
	errRev := c.RefreshTokens().Revoke(ctx, "t", "r", time.Now())
	_, _, errUG := c.UserGrants().List(ctx, "t", store.UserGrantFilter{}, store.Page{})
	_, _, errCl := c.Clients().List(ctx, "t", store.ClientFilter{AppTypes: []string{"spa"}}, store.Page{Limit: 1})
	errTkCreate := c.EmailVerificationTickets().Create(ctx, &store.EmailVerificationTicket{TenantID: "t", ID: "i", TokenHash: "h"})
	_, errTkGet := c.EmailVerificationTickets().GetByTokenHash(ctx, "t", "h")
	_, errTkUse := c.EmailVerificationTickets().Consume(ctx, "t", "h", time.Now())
	_, errTkDel := c.EmailVerificationTickets().DeleteByUser(ctx, "t", "u")
	_, errLock := c.Users().GetForUpdate(ctx, "t", "u")
	for name, err := range map[string]error{
		"Users.GetForUpdate": errLock,
		"Sessions.Get":       errSes, "Sessions.ListByUser": errSesList, "RefreshTokens.Get": errRT,
		"RefreshTokens.ListByUser": errRTList, "RefreshTokens.Revoke": errRev, "UserGrants.List": errUG,
		"EmailVerificationTickets.Create": errTkCreate, "EmailVerificationTickets.GetByTokenHash": errTkGet,
		"EmailVerificationTickets.Consume": errTkUse, "EmailVerificationTickets.DeleteByUser": errTkDel,
	} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want errPluginTooOld", name, err)
		}
	}
	// Clients.List on a plugin without ClientsListPage falls back to ClientsList,
	// which this plugin lacks too: the error is not hidden.
	if errCl == nil {
		t.Error("Clients.List with a filter on a plugin without any list RPC succeeded")
	}
	if n, err := c.EmailVerificationTickets().DeleteExpired(ctx, time.Now()); n != 0 || err != nil {
		t.Errorf("EmailVerificationTickets.DeleteExpired = %d, %v; want 0, nil", n, err)
	}
}

// clientsPlugin is a pre-Plan-17 plugin: it lists every client (by ClientID)
// and has no ClientsListPage.
type clientsPlugin struct{ oldPlugin }

func (clientsPlugin) ClientsList(context.Context, *storev1.TenantScope) (*storev1.ClientList, error) {
	mk := func(id, typ string, first bool, at int64) *storev1.Client {
		return &storev1.Client{TenantId: "t", ClientId: id, AppType: typ, CreatedAt: tsToPB(time.Unix(at, 0)), IsFirstParty: &first}
	}
	return &storev1.ClientList{Values: []*storev1.Client{
		mk("a", "spa", true, 30), mk("b", "native", true, 10), mk("c", "spa", false, 20), mk("d", "spa", true, 20),
	}}, nil
}

// GET /clients keeps working against such a plugin: the host orders, filters
// and pages what ClientsList returns.
func TestOldPluginClientsListFallback(t *testing.T) {
	c := serveWith(t, clientsPlugin{})
	ctx := context.Background()
	ids := func(f store.ClientFilter, p store.Page) ([]string, int) {
		t.Helper()
		got, total, err := c.Clients().List(ctx, "t", f, p)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, cl := range got {
			out = append(out, cl.ClientID)
		}
		return out, total
	}
	yes := true
	if got, total := ids(store.ClientFilter{}, store.Page{}); !slices.Equal(got, []string{"b", "c", "d", "a"}) || total != 4 {
		t.Errorf("all = %v, %d", got, total)
	}
	if got, total := ids(store.ClientFilter{AppTypes: []string{"spa"}, IsFirstParty: &yes}, store.Page{}); !slices.Equal(got, []string{"d", "a"}) || total != 2 {
		t.Errorf("filtered = %v, %d", got, total)
	}
	if got, total := ids(store.ClientFilter{AppTypes: []string{"spa"}}, store.Page{Offset: 1, Limit: 1}); !slices.Equal(got, []string{"d"}) || total != 3 {
		t.Errorf("paged = %v, %d", got, total)
	}
}

// Login and startup list every connection; a plugin older than Plan 15 still
// serves that. Filtered or paged lists need the new RPC.
func TestOldPluginUnfilteredConnectionList(t *testing.T) {
	c := serveWith(t, listingPlugin{})
	ctx := context.Background()
	got, total, err := c.Connections().List(ctx, "t", store.ConnectionFilter{}, store.Page{})
	if err != nil || total != 1 || len(got) != 1 || got[0].ID != "c1" {
		t.Fatalf("List = %v, %d, %v", got, total, err)
	}
	for _, tc := range []struct {
		f store.ConnectionFilter
		p store.Page
	}{{store.ConnectionFilter{Name: "Db"}, store.Page{}}, {store.ConnectionFilter{Strategies: []string{"auth0"}}, store.Page{}}, {store.ConnectionFilter{}, store.Page{Limit: 5}}} {
		if _, _, err := c.Connections().List(ctx, "t", tc.f, tc.p); !errors.Is(err, errPluginTooOld) {
			t.Errorf("List(%+v, %+v) = %v, want errPluginTooOld", tc.f, tc.p, err)
		}
	}
}

// Filtered connection lists, connection deletion and password history need a
// Plan 15 plugin.
func TestOldPluginConnectionSettingsTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	_, _, errList := c.Connections().List(ctx, "t", store.ConnectionFilter{Name: "x"}, store.Page{})
	errDelete := c.Connections().Delete(ctx, "t", "con")
	errAdd := c.PasswordHistories().Add(ctx, "t", "auth0|u", []byte("h"), 3)
	_, errHistory := c.PasswordHistories().List(ctx, "t", "auth0|u")
	for name, err := range map[string]error{"Connections.List": errList, "Connections.Delete": errDelete,
		"PasswordHistories.Add": errAdd, "PasswordHistories.List": errHistory} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want errPluginTooOld", name, err)
		}
	}
}

// Operators and tenant deletion need a Plan 13 plugin; an older one gets a
// clear error instead of a bare Unimplemented status.
func TestOldPluginOperatorsTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	_, errGet := c.Operators().Get(ctx, "t", "u")
	_, errList := c.Operators().List(ctx, "t")
	for name, err := range map[string]error{
		"Get":            errGet,
		"List":           errList,
		"Upsert":         c.Operators().Upsert(ctx, &store.Operator{TenantID: "t", UserID: "u"}),
		"Delete":         c.Operators().Delete(ctx, "t", "u"),
		"Tenants.Delete": c.Tenants().Delete(ctx, "t"),
	} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want errPluginTooOld", name, err)
		}
	}
}

func TestOldPluginSigningLifecycleTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	_, errGet := c.SigningKeys().Get(ctx, "t", "k")
	_, errRotate := c.SigningKeys().RotateWithResult(ctx, "t", &store.SigningKey{TenantID: "t", KID: "n", Status: store.KeyNext}, time.Now())
	_, errRevoke := c.SigningKeys().Revoke(ctx, "t", "k", time.Now())
	_, errCert := c.SigningKeys().SetCertificateIfAbsent(ctx, "t", "k", []byte{1})
	_, errCustomGet := c.CustomSigningKeys().Get(ctx, "t")
	errCustomReplace := c.CustomSigningKeys().Replace(ctx, &store.CustomSigningKeySet{TenantID: "t", JWKS: []byte(`{"keys":[]}`)})
	errCustomDelete := c.CustomSigningKeys().Delete(ctx, "t")
	for name, err := range map[string]error{"Get": errGet, "RotateWithResult": errRotate, "Revoke": errRevoke, "SetCertificateIfAbsent": errCert, "Custom.Get": errCustomGet, "Custom.Replace": errCustomReplace, "Custom.Delete": errCustomDelete} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want actionable plugin upgrade error", name, err)
		}
	}
}

// Users.List needs a Plan 17 plugin.
func TestOldPluginUserListTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	_, _, err := c.Users().List(context.Background(), "t", nil, store.UserSort{}, store.Page{})
	if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
		t.Errorf("err = %v, want errPluginTooOld", err)
	}
}

// Jobs and imported hashes need a Plan 18 plugin; an older one gets a clear
// error, except for the sweep, which finds no jobs.
func TestOldPluginJobsTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	ctx := context.Background()
	now := time.Now()
	_, errGet := c.Jobs().Get(ctx, "t", "j")
	_, _, errList := c.Jobs().List(ctx, "t", store.Page{})
	_, errCount := c.Jobs().CountActive(ctx, "t", store.JobUsersImport)
	_, errClaim := c.Jobs().Claim(ctx, "w", now, time.Minute)
	_, errErrors := c.Jobs().Errors(ctx, "t", "j")
	for name, err := range map[string]error{
		"Create":              c.Jobs().Create(ctx, &store.Job{TenantID: "t", ID: "j"}),
		"Get":                 errGet,
		"List":                errList,
		"CountActive":         errCount,
		"Claim":               errClaim,
		"Renew":               c.Jobs().Renew(ctx, "t", "j", "w", now),
		"Checkpoint":          c.Jobs().Checkpoint(ctx, "t", "j", "w", 1, store.JobSummary{}, nil),
		"Finish":              c.Jobs().Finish(ctx, "t", "j", "w", store.JobCompleted, "", now),
		"Errors":              errErrors,
		"AppendFile":          c.Jobs().AppendFile(ctx, "t", "j", "w", 0, []byte("x")),
		"ReadFile":            c.Jobs().ReadFile(ctx, "t", "j", func([]byte) error { return nil }),
		"UpgradeImportedHash": c.Users().UpgradeImportedHash(ctx, "t", "u", "Database", "i", "h", now),
	} {
		if !errors.Is(err, errPluginTooOld) || !strings.Contains(err.Error(), "too old") {
			t.Errorf("%s: err = %v, want errPluginTooOld", name, err)
		}
	}
	// The sweeper calls this on every deployment.
	if n, err := c.Jobs().DeleteExpired(ctx, now); n != 0 || err != nil {
		t.Errorf("DeleteExpired = %d, %v; want 0, nil", n, err)
	}
}

func TestOldPluginTenantSettingsTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	tn := &store.Tenant{ID: "t", Name: "tenant", SupportEmail: "help@example.test"}
	for _, err := range []error{c.Tenants().Create(context.Background(), tn), c.Tenants().Update(context.Background(), tn), c.Sessions().Create(context.Background(), &store.LoginSession{CookieMode: "non-persistent"})} {
		if !errors.Is(err, errPluginTooOld) {
			t.Fatalf("want plugin too old, got %v", err)
		}
	}
}

func TestOldPluginProtectionTooOld(t *testing.T) {
	c := serveOldPlugin(t)
	_, err := c.Protection().Reserve(context.Background(), nil, time.Now())
	if !errors.Is(err, errPluginTooOld) {
		t.Fatalf("want plugin too old, got %v", err)
	}
}
