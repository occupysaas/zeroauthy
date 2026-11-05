package grpcstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// webauthn.v1 carries store.WebAuthn and the Plan 33b session, client and
// tenant fields over the plugin protocol. It is negotiated by
// WebAuthnCapabilities, separately from every earlier capability, so an
// older plugin keeps working: WebAuthn calls yield ErrWebAuthnUnavailable
// and the new fields are not sent.

type clientWebAuthn struct{ c *Client }

func (c *Client) WebAuthn() store.WebAuthn { return clientWebAuthn{c} }

// CheckWebAuthnSupport latches a definitive answer for the connection.
func (c *Client) CheckWebAuthnSupport(ctx context.Context) error {
	if c.webauthnCap.v.Load() == 2 {
		return store.ErrWebAuthnUnavailable
	}
	v, err := c.rpc.WebAuthnCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("WebAuthn capability", capabilityError(err, store.ErrWebAuthnUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrWebAuthnUnavailable
		}
	}
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		c.webauthnCap.v.Store(2)
	} else if err == nil {
		c.webauthnCap.v.CompareAndSwap(0, 1)
	}
	if c.webauthnCap.v.Load() == 2 {
		return store.ErrWebAuthnUnavailable
	}
	return err
}

func (c *Client) WebAuthnSupported() bool {
	switch c.webauthnCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckWebAuthnSupport(ctx) == nil
}

func (s *Server) WebAuthnCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.WebAuthnSupporter); ok {
		if err := c.CheckWebAuthnSupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
	}
	switch s.st.WebAuthn().(type) {
	case store.UnimplementedWebAuthn, *store.UnimplementedWebAuthn:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// webauthnCall probes the capability, runs one RPC and folds its outcome
// into the latch.
func webauthnCall(ctx context.Context, c *Client, op string, call func() (*storev1.Error, error)) error {
	if err := c.CheckWebAuthnSupport(ctx); err != nil {
		return err
	}
	e, err := call()
	if err != nil {
		err = capabilityError(err, store.ErrWebAuthnUnavailable)
		if errors.Is(err, store.ErrWebAuthnUnavailable) {
			c.webauthnCap.v.Store(2)
		}
		return rpcErr(op, err)
	}
	err = errFromPB(e)
	if errors.Is(err, store.ErrWebAuthnUnavailable) {
		c.webauthnCap.v.Store(2)
	}
	return err
}

// The Plan 33b fields are dropped on write to a plugin without webauthn.v1,
// as an older plugin would drop them.
func (c *Client) webauthnTenant(t *store.Tenant) *store.Tenant {
	if t == nil || t.DomainRPIDs == nil || c.WebAuthnSupported() {
		return t
	}
	n := t.Clone()
	n.DomainRPIDs = nil
	return n
}

func (c *Client) webauthnClient(v *store.Client) *store.Client {
	if v == nil || v.Mobile == nil || c.WebAuthnSupported() {
		return v
	}
	n := *v
	n.Mobile = nil
	return &n
}

func (c *Client) webauthnSession(v *store.LoginSession) *store.LoginSession {
	if v == nil || v.AuthMethods == nil || c.WebAuthnSupported() {
		return v
	}
	n := *v
	n.AuthMethods = nil
	return &n
}

func authToMsg(a *store.Authenticator) (*storev1.MFAAuthenticator, error) {
	if a == nil {
		return nil, nil
	}
	m := &storev1.MFAAuthenticator{}
	return m, copyMFA(m, a)
}

func authFromMsg(m *storev1.MFAAuthenticator) (*store.Authenticator, error) {
	if m == nil {
		return nil, store.ErrInvalid
	}
	var a store.Authenticator
	return &a, copyMFA(&a, m)
}

func snoozeToMsg(v *store.WebAuthnSnooze) *storev1.WebAuthnSnoozeMsg {
	return &storev1.WebAuthnSnoozeMsg{TenantId: v.TenantID, UserId: v.UserID, Kind: v.Kind, ScopeKey: v.ScopeKey, Until: tsToPB(v.Until)}
}

func snoozeFromMsg(m *storev1.WebAuthnSnoozeMsg) *store.WebAuthnSnooze {
	return &store.WebAuthnSnooze{TenantID: m.TenantId, UserID: m.UserId, Kind: m.Kind, ScopeKey: m.ScopeKey, Until: tsFromPB(m.Until)}
}

// ---- client ----

func (o clientWebAuthn) GetAuthenticatorByCredentialID(ctx context.Context, tid string, credID []byte) (*store.Authenticator, error) {
	var out *store.Authenticator
	err := webauthnCall(ctx, o.c, "WebAuthnGetByCredentialID", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnGetByCredentialID(ctx, &storev1.WebAuthnCredentialRequest{TxId: o.c.txID, Tid: tid, CredentialId: credID})
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		out, err = authFromMsg(r.GetValue())
		return nil, err
	})
	return out, err
}

func (o clientWebAuthn) CreatePasskey(ctx context.Context, a *store.Authenticator, limit int) error {
	m, err := authToMsg(a)
	if err != nil {
		return err
	}
	return webauthnCall(ctx, o.c, "WebAuthnCreatePasskey", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnCreatePasskey(ctx, &storev1.WebAuthnCreatePasskeyRequest{TxId: o.c.txID, V: m, Limit: int64(limit)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) CreateUserWithPasskey(ctx context.Context, u *store.User, a *store.Authenticator) error {
	m, err := authToMsg(a)
	if err != nil {
		return err
	}
	pu, err := userToPB(u)
	if err != nil {
		return err
	}
	return webauthnCall(ctx, o.c, "WebAuthnCreateUserWithPasskey", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnCreateUserWithPasskey(ctx, &storev1.WebAuthnCreateUserWithPasskeyRequest{TxId: o.c.txID, User: pu, V: m})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) AcceptAssertion(ctx context.Context, tid, uid, id string, count uint32, backedUp bool, at time.Time) error {
	return webauthnCall(ctx, o.c, "WebAuthnAcceptAssertion", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnAcceptAssertion(ctx, &storev1.WebAuthnAcceptAssertionRequest{TxId: o.c.txID, Tid: tid, Uid: uid, Id: id, Count: count, BackedUp: backedUp, At: tsToPB(at)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) MovePasskeys(ctx context.Context, tid, fromUID, toUID, identityUserID string) error {
	return webauthnCall(ctx, o.c, "WebAuthnMovePasskeys", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnMovePasskeys(ctx, &storev1.WebAuthnMovePasskeysRequest{TxId: o.c.txID, Tid: tid, FromUid: fromUID, ToUid: toUID, IdentityUserId: identityUserID})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) PutSnooze(ctx context.Context, v *store.WebAuthnSnooze) error {
	return webauthnCall(ctx, o.c, "WebAuthnPutSnooze", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnPutSnooze(ctx, &storev1.WebAuthnPutSnoozeRequest{TxId: o.c.txID, V: snoozeToMsg(v)})
		return r.GetError(), err
	})
}

func (o clientWebAuthn) GetSnooze(ctx context.Context, tid, uid, kind, scope string, now time.Time) (*store.WebAuthnSnooze, error) {
	var out *store.WebAuthnSnooze
	err := webauthnCall(ctx, o.c, "WebAuthnGetSnooze", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnGetSnooze(ctx, &storev1.WebAuthnGetSnoozeRequest{TxId: o.c.txID, Tid: tid, Uid: uid, Kind: kind, Scope: scope, Now: tsToPB(now)})
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		if r.GetValue() == nil {
			return nil, store.ErrInvalid
		}
		out = snoozeFromMsg(r.GetValue())
		return nil, nil
	})
	return out, err
}

func (o clientWebAuthn) HostTenantsUnder(ctx context.Context, suffix string, limit int) ([]string, error) {
	var out []string
	err := webauthnCall(ctx, o.c, "WebAuthnHostTenantsUnder", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnHostTenantsUnder(ctx, &storev1.WebAuthnHostTenantsRequest{TxId: o.c.txID, Suffix: suffix, Limit: int64(limit)})
		out = append([]string{}, r.GetTenantIds()...)
		return r.GetError(), err
	})
	return out, err
}

func (o clientWebAuthn) PurgeWebAuthn(ctx context.Context, before time.Time, limit int) (int, error) {
	var n int
	err := webauthnCall(ctx, o.c, "WebAuthnPurge", func() (*storev1.Error, error) {
		r, err := o.c.rpc.WebAuthnPurge(ctx, &storev1.WebAuthnPurgeRequest{TxId: o.c.txID, Before: tsToPB(before), Limit: int64(limit)})
		n = int(r.GetCount())
		return r.GetError(), err
	})
	return n, err
}

// ---- server ----

func (s *Server) WebAuthnGetByCredentialID(ctx context.Context, q *storev1.WebAuthnCredentialRequest) (*storev1.WebAuthnAuthenticatorResponse, error) {
	out := &storev1.WebAuthnAuthenticatorResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		a, err := st.WebAuthn().GetAuthenticatorByCredentialID(ctx, q.GetTid(), q.GetCredentialId())
		if err != nil {
			return err
		}
		out.Value, err = authToMsg(a)
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnCreatePasskey(ctx context.Context, q *storev1.WebAuthnCreatePasskeyRequest) (*storev1.WebAuthnErrorResponse, error) {
	a, err := authFromMsg(q.GetV())
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().CreatePasskey(ctx, a, int(q.GetLimit()))
	}))}, nil
}

func (s *Server) WebAuthnCreateUserWithPasskey(ctx context.Context, q *storev1.WebAuthnCreateUserWithPasskeyRequest) (*storev1.WebAuthnErrorResponse, error) {
	a, err := authFromMsg(q.GetV())
	if err != nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	u, err := userFromPB(q.GetUser())
	if err != nil || u == nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().CreateUserWithPasskey(ctx, u, a)
	}))}, nil
}

func (s *Server) WebAuthnAcceptAssertion(ctx context.Context, q *storev1.WebAuthnAcceptAssertionRequest) (*storev1.WebAuthnErrorResponse, error) {
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().AcceptAssertion(ctx, q.GetTid(), q.GetUid(), q.GetId(), q.GetCount(), q.GetBackedUp(), tsFromPB(q.GetAt()))
	}))}, nil
}

func (s *Server) WebAuthnMovePasskeys(ctx context.Context, q *storev1.WebAuthnMovePasskeysRequest) (*storev1.WebAuthnErrorResponse, error) {
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().MovePasskeys(ctx, q.GetTid(), q.GetFromUid(), q.GetToUid(), q.GetIdentityUserId())
	}))}, nil
}

func (s *Server) WebAuthnPutSnooze(ctx context.Context, q *storev1.WebAuthnPutSnoozeRequest) (*storev1.WebAuthnErrorResponse, error) {
	if q.GetV() == nil {
		return &storev1.WebAuthnErrorResponse{Error: errToPB(store.ErrInvalid)}, nil
	}
	return &storev1.WebAuthnErrorResponse{Error: errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		return st.WebAuthn().PutSnooze(ctx, snoozeFromMsg(q.GetV()))
	}))}, nil
}

func (s *Server) WebAuthnGetSnooze(ctx context.Context, q *storev1.WebAuthnGetSnoozeRequest) (*storev1.WebAuthnSnoozeResponse, error) {
	out := &storev1.WebAuthnSnoozeResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.WebAuthn().GetSnooze(ctx, q.GetTid(), q.GetUid(), q.GetKind(), q.GetScope(), tsFromPB(q.GetNow()))
		if err == nil {
			out.Value = snoozeToMsg(v)
		}
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnHostTenantsUnder(ctx context.Context, q *storev1.WebAuthnHostTenantsRequest) (*storev1.WebAuthnHostTenantsResponse, error) {
	out := &storev1.WebAuthnHostTenantsResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		ids, err := st.WebAuthn().HostTenantsUnder(ctx, q.GetSuffix(), int(q.GetLimit()))
		out.TenantIds = ids
		return err
	}))
	return out, nil
}

func (s *Server) WebAuthnPurge(ctx context.Context, q *storev1.WebAuthnPurgeRequest) (*storev1.WebAuthnCountResponse, error) {
	out := &storev1.WebAuthnCountResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		n, err := st.WebAuthn().PurgeWebAuthn(ctx, tsFromPB(q.GetBefore()), int(q.GetLimit()))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}
