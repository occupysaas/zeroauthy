package grpcstore

import (
	"context"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"time"
)

type clientConnectionKeys struct{ c *Client }

func (c *Client) ConnectionKeys() store.ConnectionKeys {
	if c.ckCap.v.Load() == 2 {
		return store.UnimplementedConnectionKeys{}
	}
	return clientConnectionKeys{c}
}

// CheckConnectionKeysSupport latches a definitive answer for the connection.
func (c *Client) CheckConnectionKeysSupport(ctx context.Context) error {
	switch c.ckCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrConnectionKeysUnavailable
	}
	v, err := c.rpc.ConnectionKeysCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("ConnectionKeys capability", capabilityError(err, store.ErrConnectionKeysUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrConnectionKeysUnavailable
		}
	}
	if errors.Is(err, store.ErrConnectionKeysUnavailable) {
		c.ckCap.v.Store(2)
	} else if err == nil {
		c.ckCap.v.CompareAndSwap(0, 1)
	}
	if c.ckCap.v.Load() == 2 {
		return store.ErrConnectionKeysUnavailable
	}
	return err
}

func (c *Client) ConnectionKeysSupported() bool {
	switch c.ckCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckConnectionKeysSupport(ctx) == nil
}

func (s *Server) ConnectionKeysCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.ConnectionKeysSupporter); ok {
		if !c.ConnectionKeysSupported() {
			return &storev1.EventsCapabilitiesResult{}, nil
		}
	}
	switch s.st.ConnectionKeys().(type) {
	case store.UnimplementedConnectionKeys, *store.UnimplementedConnectionKeys:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

func connectionKeyToMsg(k *store.ConnectionKey) *storev1.ConnectionKeyMsg {
	if k == nil {
		return nil
	}
	return &storev1.ConnectionKeyMsg{TenantId: k.TenantID, ConnectionId: k.ConnectionID, Kid: k.KID, KeyUse: k.Use, Alg: k.Alg, State: k.State, CertDer: cloneBytes(k.CertDER), PrivateSealed: cloneBytes(k.PrivateSealed), CurrentSince: optTSToPB(k.CurrentSince), CreatedAt: tsToPB(k.CreatedAt)}
}
func connectionKeyFromMsg(k *storev1.ConnectionKeyMsg) (*store.ConnectionKey, error) {
	if k == nil {
		return nil, store.ErrInvalid
	}
	if e := checkTS(k.CreatedAt); e != nil {
		return nil, e
	}
	if e := checkTS(k.CurrentSince); e != nil {
		return nil, e
	}
	return &store.ConnectionKey{TenantID: k.TenantId, ConnectionID: k.ConnectionId, KID: k.Kid, Use: k.KeyUse, Alg: k.Alg, State: k.State, CertDER: cloneBytes(k.CertDer), PrivateSealed: cloneBytes(k.PrivateSealed), CurrentSince: optTSFromPB(k.CurrentSince), CreatedAt: tsFromPB(k.CreatedAt)}, nil
}
func (r clientConnectionKeys) request(tid, cid, use string) *storev1.ConnectionKeysRequest {
	return &storev1.ConnectionKeysRequest{TxId: r.c.txID, Tid: tid, ConnectionId: cid, KeyUse: use}
}
func (r clientConnectionKeys) result(op string, v *storev1.ConnectionKeysResult, err error) ([]*store.ConnectionKey, error) {
	if err != nil {
		e := capabilityError(err, store.ErrConnectionKeysUnavailable)
		if errors.Is(e, store.ErrConnectionKeysUnavailable) {
			r.c.ckCap.v.Store(2)
		}
		return nil, rpcErr(op, e)
	}
	if e := errFromPB(v.GetError()); e != nil {
		if errors.Is(e, store.ErrConnectionKeysUnavailable) {
			r.c.ckCap.v.Store(2)
		}
		return nil, e
	}
	out := []*store.ConnectionKey{}
	for _, m := range v.GetValues() {
		k, e := connectionKeyFromMsg(m)
		if e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, nil
}
func (r clientConnectionKeys) List(ctx context.Context, tid, cid string) ([]*store.ConnectionKey, error) {
	if e := r.c.CheckConnectionKeysSupport(ctx); e != nil {
		return nil, e
	}
	v, e := r.c.rpc.ListConnectionKeys(ctx, r.request(tid, cid, ""))
	return r.result("ListConnectionKeys", v, e)
}
func (r clientConnectionKeys) Create(ctx context.Context, tid, cid, use string, current, next *store.ConnectionKey) error {
	if e := r.c.CheckConnectionKeysSupport(ctx); e != nil {
		return e
	}
	q := r.request(tid, cid, use)
	q.Current, q.Next = connectionKeyToMsg(current), connectionKeyToMsg(next)
	v, e := r.c.rpc.CreateConnectionKeys(ctx, q)
	if e != nil {
		return rpcErr("CreateConnectionKeys", capabilityError(e, store.ErrConnectionKeysUnavailable))
	}
	return errFromPB(v.GetError())
}
func (r clientConnectionKeys) Rotate(ctx context.Context, tid, cid, use string, next *store.ConnectionKey, now time.Time) (*store.ConnectionKey, error) {
	if e := r.c.CheckConnectionKeysSupport(ctx); e != nil {
		return nil, e
	}
	q := r.request(tid, cid, use)
	q.Next, q.Now = connectionKeyToMsg(next), tsToPB(now)
	v, e := r.c.rpc.RotateConnectionKeys(ctx, q)
	keys, e := r.result("RotateConnectionKeys", v, e)
	if e != nil {
		return nil, e
	}
	if len(keys) != 1 {
		return nil, store.ErrInvalid
	}
	return keys[0], nil
}
func (s *Server) ListConnectionKeys(ctx context.Context, q *storev1.ConnectionKeysRequest) (*storev1.ConnectionKeysResult, error) {
	out := &storev1.ConnectionKeysResult{}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		keys, e := st.ConnectionKeys().List(ctx, q.Tid, q.ConnectionId)
		for _, k := range keys {
			out.Values = append(out.Values, connectionKeyToMsg(k))
		}
		return e
	}))
	return out, nil
}
func (s *Server) CreateConnectionKeys(ctx context.Context, q *storev1.ConnectionKeysRequest) (*storev1.Result, error) {
	a, e := connectionKeyFromMsg(q.Current)
	if e != nil {
		return &storev1.Result{Error: errToPB(e)}, nil
	}
	b, e := connectionKeyFromMsg(q.Next)
	if e != nil {
		return &storev1.Result{Error: errToPB(e)}, nil
	}
	return exec(s, q.TxId, func(st store.Store) error {
		return st.ConnectionKeys().Create(ctx, q.Tid, q.ConnectionId, q.KeyUse, a, b)
	}), nil
}
func (s *Server) RotateConnectionKeys(ctx context.Context, q *storev1.ConnectionKeysRequest) (*storev1.ConnectionKeysResult, error) {
	out := &storev1.ConnectionKeysResult{}
	next, e := connectionKeyFromMsg(q.Next)
	if e != nil {
		out.Error = errToPB(e)
		return out, nil
	}
	if e = checkTS(q.Now); e != nil {
		out.Error = errToPB(e)
		return out, nil
	}
	out.Error = errToPB(s.with(q.TxId, func(st store.Store) error {
		k, e := st.ConnectionKeys().Rotate(ctx, q.Tid, q.ConnectionId, q.KeyUse, next, tsFromPB(q.Now))
		if e == nil {
			out.Values = []*storev1.ConnectionKeyMsg{connectionKeyToMsg(k)}
		}
		return e
	}))
	return out, nil
}
