package grpcstore

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// Client is a store.Store backed by a StoreService. A Client with a txID is
// a transactional view handed to WithTx callbacks.
type Client struct {
	rpc    storev1.StoreServiceClient
	closer func() error
	txID   string // empty outside a transaction
}

var _ store.Store = (*Client)(nil)

// NewClient returns a store over conn. Close calls closer, which may be nil.
func NewClient(conn grpc.ClientConnInterface, closer func() error) *Client {
	return &Client{rpc: storev1.NewStoreServiceClient(conn), closer: closer}
}

// rpcErr wraps a transport failure so it never matches a store sentinel.
// A cancelled or expired context is reported as the matching context error,
// with the gRPC status kept in the chain.
func rpcErr(op string, err error) error {
	switch status.Code(err) {
	case codes.Canceled:
		return fmt.Errorf("storage plugin: %s: %w: %w", op, context.Canceled, err)
	case codes.DeadlineExceeded:
		return fmt.Errorf("storage plugin: %s: %w: %w", op, context.DeadlineExceeded, err)
	}
	return fmt.Errorf("storage plugin: %s: %w", op, err)
}

func (c *Client) Ping(ctx context.Context) error {
	r, err := c.rpc.Ping(ctx, &storev1.PingRequest{})
	if err != nil {
		return rpcErr("Ping", err)
	}
	return errFromPB(r.GetError())
}

// Close releases the connection. It is a no-op on a transactional view.
func (c *Client) Close() error {
	if c.txID != "" || c.closer == nil {
		return nil
	}
	return c.closer()
}

// WithTx opens a remote transaction (nested when c is already inside one),
// runs fn against a view bound to it, and commits only if fn returns nil.
// It never retries. A panic in fn rolls back and is re-raised.
//
// The server treats a transaction tree as a stack: inside a nested fn, only
// the innermost tx store may be used until that fn returns. Using an
// ancestor view meanwhile fails with an "open nested transaction" error.
// A tx store must not be used after its fn returns.
func (c *Client) WithTx(ctx context.Context, fn func(store.Store) error) (err error) {
	r, rerr := c.rpc.BeginTx(ctx, &storev1.BeginTxRequest{ParentTxId: c.txID})
	if rerr != nil {
		return rpcErr("BeginTx", rerr)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return e
	}
	tx := &Client{rpc: c.rpc, txID: r.TxId}
	end := context.WithoutCancel(ctx)
	committed, commitFailed := false, false
	defer func() {
		if committed {
			return
		}
		// Reached on an fn error, a panic, or a failed Commit. A rollback
		// failure is only reported when fn failed; after a failed Commit the
		// Commit error stands, and during a panic the panic keeps propagating.
		if _, rbErr := c.rpc.Rollback(end, &storev1.EndTxRequest{TxId: r.TxId}); rbErr != nil && err != nil && !commitFailed {
			err = errors.Join(err, rpcErr("Rollback", rbErr))
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	cr, cerr := c.rpc.Commit(end, &storev1.EndTxRequest{TxId: r.TxId})
	commitFailed = true
	if cerr == nil {
		cerr2 := errFromPB(cr.GetError())
		if cerr2 == nil {
			committed, commitFailed = true, false
			return nil
		}
		err = cerr2
	} else {
		err = rpcErr("Commit", cerr)
	}
	// A failed Commit may leave the transaction open (a transport error, an
	// open nested transaction). The deferred Rollback is a best effort so it
	// does not linger until the idle timeout; its result is ignored.
	return err
}

func (c *Client) Tenants() store.Tenants                       { return clientTenants{c} }
func (c *Client) Clients() store.Clients                       { return clientClients{c} }
func (c *Client) ResourceServers() store.ResourceServers       { return clientResourceServers{c} }
func (c *Client) ClientGrants() store.ClientGrants             { return clientClientGrants{c} }
func (c *Client) UserGrants() store.UserGrants                 { return clientUserGrants{c} }
func (c *Client) SigningKeys() store.SigningKeys               { return clientSigningKeys{c} }
func (c *Client) Connections() store.Connections               { return clientConnections{c} }
func (c *Client) Users() store.Users                           { return clientUsers{c} }
func (c *Client) Sessions() store.Sessions                     { return clientSessions{c} }
func (c *Client) AuthTransactions() store.AuthTransactions     { return clientAuthTransactions{c} }
func (c *Client) AuthCodes() store.AuthCodes                   { return clientAuthCodes{c} }
func (c *Client) PushedAuthRequests() store.PushedAuthRequests { return clientPushedAuthRequests{c} }
func (c *Client) DeviceCodes() store.DeviceCodes               { return clientDeviceCodes{c} }
func (c *Client) RefreshTokens() store.RefreshTokens           { return clientRefreshTokens{c} }
func (c *Client) Operators() store.Operators                   { return clientOperators{c} }
func (c *Client) PasswordResetTickets() store.PasswordResetTickets {
	return clientPasswordResetTickets{c}
}
