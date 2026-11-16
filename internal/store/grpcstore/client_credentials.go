package grpcstore

import (
	"context"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// client_credentials.v1 carries store.ClientCredentials and the Plan 35
// client, API and pushed-request fields over the plugin protocol. It is
// negotiated by ClientCredentialsCapabilities, separately from every earlier
// capability, so an older plugin keeps working: calls yield
// ErrClientCredentialsUnavailable and the new fields are not sent.

type clientClientCredentials struct{ c *Client }

func (c *Client) ClientCredentials() store.ClientCredentials { return clientClientCredentials{c} }

// CheckClientCredentialsSupport latches a definitive answer for the connection.
func (c *Client) CheckClientCredentialsSupport(ctx context.Context) error {
	switch c.ccCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrClientCredentialsUnavailable
	}
	v, err := c.rpc.ClientCredentialsCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("ClientCredentials capability", capabilityError(err, store.ErrClientCredentialsUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrClientCredentialsUnavailable
		}
	}
	if errors.Is(err, store.ErrClientCredentialsUnavailable) {
		c.ccCap.v.Store(2)
	} else if err == nil {
		c.ccCap.v.CompareAndSwap(0, 1)
	}
	if c.ccCap.v.Load() == 2 {
		return store.ErrClientCredentialsUnavailable
	}
	return err
}

func (c *Client) ClientCredentialsSupported() bool {
	switch c.ccCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckClientCredentialsSupport(ctx) == nil
}

func (s *Server) ClientCredentialsCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.ClientCredentialsSupporter); ok {
		if err := c.CheckClientCredentialsSupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
	}
	switch s.st.ClientCredentials().(type) {
	case store.UnimplementedClientCredentials, *store.UnimplementedClientCredentials:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// ccCall probes the capability, runs one RPC and folds its outcome into the
// latch.
func ccCall(ctx context.Context, c *Client, op string, call func() (*storev1.Error, error)) error {
	if err := c.CheckClientCredentialsSupport(ctx); err != nil {
		return err
	}
	e, err := call()
	if err != nil {
		err = capabilityError(err, store.ErrClientCredentialsUnavailable)
		if errors.Is(err, store.ErrClientCredentialsUnavailable) {
			c.ccCap.v.Store(2)
		}
		return rpcErr(op, err)
	}
	err = errFromPB(e)
	if errors.Is(err, store.ErrClientCredentialsUnavailable) {
		c.ccCap.v.Store(2)
	}
	return err
}

// The Plan 35 fields are dropped on write to a plugin without
// client_credentials.v1, as an older plugin would drop them.
func (c *Client) clientCredentialsClient(v *store.Client) *store.Client {
	if v == nil || v.PrivateKeyJWTCredentials == nil && v.SignedRequestObject == nil && v.TokenExchangeTypes == nil || c.ClientCredentialsSupported() {
		return v
	}
	n := *v
	n.PrivateKeyJWTCredentials, n.SignedRequestObject, n.TokenExchangeTypes = nil, nil, nil
	return &n
}

func (c *Client) clientCredentialsResourceServer(v *store.ResourceServer) *store.ResourceServer {
	if v == nil || v.SigningSecretSealed == nil || c.ClientCredentialsSupported() {
		return v
	}
	n := *v
	n.SigningSecretSealed = nil
	return &n
}

func (c *Client) clientCredentialsPAR(v *store.PushedAuthRequest) *store.PushedAuthRequest {
	if v == nil || !v.Signed || c.ClientCredentialsSupported() {
		return v
	}
	n := *v
	n.Signed = false
	return &n
}

// ---- client fields ----

// JSON shapes of the three client settings; a nil slice is encoded as null so
// unset and empty survive the wire.
type wirePrivateKeyJWT struct {
	PrivateKeyJWT *struct {
		Credentials []string `json:"credentials"`
	} `json:"private_key_jwt"`
}

type wireSignedRequestObject struct {
	Required    bool     `json:"required"`
	Credentials []string `json:"credentials"`
}

type wireTokenExchange struct {
	AllowAnyProfileOfType []string `json:"allow_any_profile_of_type"`
}

func clientCredentialFieldsToPB(c *store.Client, pb *storev1.Client) error {
	var err error
	if c.PrivateKeyJWTCredentials != nil {
		w := wirePrivateKeyJWT{PrivateKeyJWT: &struct {
			Credentials []string `json:"credentials"`
		}{c.PrivateKeyJWTCredentials}}
		if pb.ClientAuthenticationMethods, err = optJSON(w, false); err != nil {
			return err
		}
	}
	if c.SignedRequestObject != nil {
		w := wireSignedRequestObject{Required: c.SignedRequestObject.Required, Credentials: c.SignedRequestObject.Credentials}
		if pb.SignedRequestObject, err = optJSON(w, false); err != nil {
			return err
		}
	}
	if c.TokenExchangeTypes != nil {
		if pb.TokenExchange, err = optJSON(wireTokenExchange{c.TokenExchangeTypes}, false); err != nil {
			return err
		}
	}
	return nil
}

func clientCredentialFieldsFromPB(pb *storev1.Client, c *store.Client) error {
	if len(pb.ClientAuthenticationMethods) > 0 {
		var w wirePrivateKeyJWT
		if err := fromOptJSON(pb.ClientAuthenticationMethods, &w); err != nil {
			return err
		}
		if w.PrivateKeyJWT != nil {
			c.PrivateKeyJWTCredentials = w.PrivateKeyJWT.Credentials
		}
	}
	if len(pb.SignedRequestObject) > 0 {
		var w wireSignedRequestObject
		if err := fromOptJSON(pb.SignedRequestObject, &w); err != nil {
			return err
		}
		c.SignedRequestObject = &store.SignedRequestObject{Required: w.Required, Credentials: w.Credentials}
	}
	if len(pb.TokenExchange) > 0 {
		var w wireTokenExchange
		if err := fromOptJSON(pb.TokenExchange, &w); err != nil {
			return err
		}
		c.TokenExchangeTypes = w.AllowAnyProfileOfType
	}
	return nil
}

// ---- messages ----

func credentialToMsg(c *store.ClientCredential) *storev1.ClientCredentialMsg {
	if c == nil {
		return nil
	}
	return &storev1.ClientCredentialMsg{TenantId: c.TenantID, ClientId: c.ClientID, Id: c.ID, Type: c.Type, Name: c.Name,
		Kid: c.KID, Alg: c.Alg, PublicKeyDer: cloneBytes(c.PublicKeyDER), Thumbprint: c.Thumbprint,
		ExpiresAt: optTSToPB(c.ExpiresAt), CreatedAt: tsToPB(c.CreatedAt), UpdatedAt: tsToPB(c.UpdatedAt)}
}

func credentialFromMsg(m *storev1.ClientCredentialMsg) (*store.ClientCredential, error) {
	if m == nil {
		return nil, nil
	}
	if err := checkTS(m.ExpiresAt, m.CreatedAt, m.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.ClientCredential{TenantID: m.TenantId, ClientID: m.ClientId, ID: m.Id, Type: m.Type, Name: m.Name,
		KID: m.Kid, Alg: m.Alg, PublicKeyDER: cloneBytes(m.PublicKeyDer), Thumbprint: m.Thumbprint,
		ExpiresAt: optTSFromPB(m.ExpiresAt), CreatedAt: tsFromPB(m.CreatedAt), UpdatedAt: tsFromPB(m.UpdatedAt)}, nil
}

func profileToMsg(p *store.TokenExchangeProfile) *storev1.TokenExchangeProfileMsg {
	if p == nil {
		return nil
	}
	return &storev1.TokenExchangeProfileMsg{TenantId: p.TenantID, Id: p.ID, Name: p.Name, SubjectTokenType: p.SubjectTokenType,
		ActionId: p.ActionID, Type: p.Type, CreatedAt: tsToPB(p.CreatedAt), UpdatedAt: tsToPB(p.UpdatedAt)}
}

func profileFromMsg(m *storev1.TokenExchangeProfileMsg) (*store.TokenExchangeProfile, error) {
	if m == nil {
		return nil, nil
	}
	if err := checkTS(m.CreatedAt, m.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.TokenExchangeProfile{TenantID: m.TenantId, ID: m.Id, Name: m.Name, SubjectTokenType: m.SubjectTokenType,
		ActionID: m.ActionId, Type: m.Type, CreatedAt: tsFromPB(m.CreatedAt), UpdatedAt: tsFromPB(m.UpdatedAt)}, nil
}

// ---- client ----

func (o clientClientCredentials) Create(ctx context.Context, v *store.ClientCredential, limit int) error {
	if v == nil {
		return store.ErrInvalid
	}
	return ccCall(ctx, o.c, "ClientCredentialsCreate", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsCreate(ctx, &storev1.ClientCredentialsCreateRequest{TxId: o.c.txID, V: credentialToMsg(v), Limit: int64(limit)})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) Get(ctx context.Context, tid, clientID, id string) (*store.ClientCredential, error) {
	var out *store.ClientCredential
	err := ccCall(ctx, o.c, "ClientCredentialsGet", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsGet(ctx, &storev1.ClientCredentialKeyRequest{TxId: o.c.txID, Tid: tid, ClientId: clientID, Id: id})
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		if r.GetValue() == nil {
			return nil, store.ErrInvalid
		}
		out, err = credentialFromMsg(r.GetValue())
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o clientClientCredentials) List(ctx context.Context, tid, clientID string) ([]*store.ClientCredential, error) {
	var out []*store.ClientCredential
	err := ccCall(ctx, o.c, "ClientCredentialsList", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsList(ctx, &storev1.ClientCredentialListRequest{TxId: o.c.txID, Tid: tid, ClientId: clientID})
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		for _, m := range r.GetValues() {
			c, err := credentialFromMsg(m)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
		return nil, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o clientClientCredentials) UpdateExpiry(ctx context.Context, tid, clientID, id string, exp *time.Time) error {
	return ccCall(ctx, o.c, "ClientCredentialsUpdateExpiry", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsUpdateExpiry(ctx, &storev1.ClientCredentialsUpdateExpiryRequest{TxId: o.c.txID, Tid: tid, ClientId: clientID, Id: id, ExpiresAt: optTSToPB(exp)})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) Delete(ctx context.Context, tid, clientID, id string) error {
	return ccCall(ctx, o.c, "ClientCredentialsDelete", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsDelete(ctx, &storev1.ClientCredentialKeyRequest{TxId: o.c.txID, Tid: tid, ClientId: clientID, Id: id})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) UseJTI(ctx context.Context, tid, clientID, jti string, exp time.Time) error {
	return ccCall(ctx, o.c, "ClientCredentialsUseJTI", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsUseJTI(ctx, &storev1.ClientCredentialsUseJTIRequest{TxId: o.c.txID, Tid: tid, ClientId: clientID, Jti: jti, ExpiresAt: tsToPB(exp)})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) PurgeJTIs(ctx context.Context, before time.Time, limit int) (int, error) {
	var n int
	err := ccCall(ctx, o.c, "ClientCredentialsPurgeJTIs", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsPurgeJTIs(ctx, &storev1.ClientCredentialsPurgeRequest{TxId: o.c.txID, Before: tsToPB(before), Limit: int64(limit)})
		n = int(r.GetCount())
		return r.GetError(), err
	})
	return n, err
}

func (o clientClientCredentials) CreateProfile(ctx context.Context, p *store.TokenExchangeProfile, limit int) error {
	if p == nil {
		return store.ErrInvalid
	}
	return ccCall(ctx, o.c, "ClientCredentialsCreateProfile", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsCreateProfile(ctx, &storev1.TokenExchangeProfileCreateRequest{TxId: o.c.txID, V: profileToMsg(p), Limit: int64(limit)})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) profile(ctx context.Context, op string, call func() (*storev1.TokenExchangeProfileResult, error)) (*store.TokenExchangeProfile, error) {
	var out *store.TokenExchangeProfile
	err := ccCall(ctx, o.c, op, func() (*storev1.Error, error) {
		r, err := call()
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		if r.GetValue() == nil {
			return nil, store.ErrInvalid
		}
		out, err = profileFromMsg(r.GetValue())
		return nil, err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (o clientClientCredentials) GetProfile(ctx context.Context, tid, id string) (*store.TokenExchangeProfile, error) {
	return o.profile(ctx, "ClientCredentialsGetProfile", func() (*storev1.TokenExchangeProfileResult, error) {
		return o.c.rpc.ClientCredentialsGetProfile(ctx, &storev1.TokenExchangeProfileKeyRequest{TxId: o.c.txID, Tid: tid, Key: id})
	})
}

func (o clientClientCredentials) GetProfileByType(ctx context.Context, tid, subjectTokenType string) (*store.TokenExchangeProfile, error) {
	return o.profile(ctx, "ClientCredentialsGetProfileByType", func() (*storev1.TokenExchangeProfileResult, error) {
		return o.c.rpc.ClientCredentialsGetProfileByType(ctx, &storev1.TokenExchangeProfileKeyRequest{TxId: o.c.txID, Tid: tid, Key: subjectTokenType})
	})
}

func (o clientClientCredentials) ListProfiles(ctx context.Context, tid, from string, take int) ([]*store.TokenExchangeProfile, string, error) {
	var (
		out  []*store.TokenExchangeProfile
		next string
	)
	err := ccCall(ctx, o.c, "ClientCredentialsListProfiles", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsListProfiles(ctx, &storev1.TokenExchangeProfileListRequest{TxId: o.c.txID, Tid: tid, From: from, Take: int64(take)})
		if err != nil || r.GetError() != nil {
			return r.GetError(), err
		}
		for _, m := range r.GetValues() {
			p, err := profileFromMsg(m)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		next = r.GetNext()
		return nil, nil
	})
	if err != nil {
		return nil, "", err
	}
	return out, next, nil
}

func (o clientClientCredentials) UpdateProfile(ctx context.Context, p *store.TokenExchangeProfile) error {
	if p == nil {
		return store.ErrInvalid
	}
	return ccCall(ctx, o.c, "ClientCredentialsUpdateProfile", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsUpdateProfile(ctx, &storev1.TokenExchangeProfileWrite{TxId: o.c.txID, V: profileToMsg(p)})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) DeleteProfile(ctx context.Context, tid, id string) error {
	return ccCall(ctx, o.c, "ClientCredentialsDeleteProfile", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsDeleteProfile(ctx, &storev1.TokenExchangeProfileKeyRequest{TxId: o.c.txID, Tid: tid, Key: id})
		return r.GetError(), err
	})
}

func (o clientClientCredentials) ProfilesForAction(ctx context.Context, tid, actionID string) (int, error) {
	var n int
	err := ccCall(ctx, o.c, "ClientCredentialsProfilesForAction", func() (*storev1.Error, error) {
		r, err := o.c.rpc.ClientCredentialsProfilesForAction(ctx, &storev1.TokenExchangeProfileKeyRequest{TxId: o.c.txID, Tid: tid, Key: actionID})
		n = int(r.GetCount())
		return r.GetError(), err
	})
	return n, err
}

// ---- server ----

func (s *Server) ClientCredentialsCreate(ctx context.Context, q *storev1.ClientCredentialsCreateRequest) (*storev1.Result, error) {
	v, err := credentialFromMsg(q.GetV())
	if err != nil || v == nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.GetTxId(), func(st store.Store) error { return st.ClientCredentials().Create(ctx, v, int(q.GetLimit())) }), nil
}

func (s *Server) ClientCredentialsGet(ctx context.Context, q *storev1.ClientCredentialKeyRequest) (*storev1.ClientCredentialResult, error) {
	out := &storev1.ClientCredentialResult{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.ClientCredentials().Get(ctx, q.GetTid(), q.GetClientId(), q.GetId())
		if err == nil {
			out.Value = credentialToMsg(v)
		}
		return err
	}))
	return out, nil
}

func (s *Server) ClientCredentialsList(ctx context.Context, q *storev1.ClientCredentialListRequest) (*storev1.ClientCredentialListResult, error) {
	out := &storev1.ClientCredentialListResult{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		vs, err := st.ClientCredentials().List(ctx, q.GetTid(), q.GetClientId())
		for _, v := range vs {
			out.Values = append(out.Values, credentialToMsg(v))
		}
		return err
	}))
	return out, nil
}

func (s *Server) ClientCredentialsUpdateExpiry(ctx context.Context, q *storev1.ClientCredentialsUpdateExpiryRequest) (*storev1.Result, error) {
	if err := checkTS(q.GetExpiresAt()); err != nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.GetTxId(), func(st store.Store) error {
		return st.ClientCredentials().UpdateExpiry(ctx, q.GetTid(), q.GetClientId(), q.GetId(), optTSFromPB(q.GetExpiresAt()))
	}), nil
}

func (s *Server) ClientCredentialsDelete(ctx context.Context, q *storev1.ClientCredentialKeyRequest) (*storev1.Result, error) {
	return exec(s, q.GetTxId(), func(st store.Store) error {
		return st.ClientCredentials().Delete(ctx, q.GetTid(), q.GetClientId(), q.GetId())
	}), nil
}

func (s *Server) ClientCredentialsUseJTI(ctx context.Context, q *storev1.ClientCredentialsUseJTIRequest) (*storev1.Result, error) {
	if err := checkTS(q.GetExpiresAt()); err != nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.GetTxId(), func(st store.Store) error {
		return st.ClientCredentials().UseJTI(ctx, q.GetTid(), q.GetClientId(), q.GetJti(), tsFromPB(q.GetExpiresAt()))
	}), nil
}

func (s *Server) ClientCredentialsPurgeJTIs(ctx context.Context, q *storev1.ClientCredentialsPurgeRequest) (*storev1.CountResult, error) {
	out := &storev1.CountResult{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		n, err := st.ClientCredentials().PurgeJTIs(ctx, tsFromPB(q.GetBefore()), int(q.GetLimit()))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}

func (s *Server) ClientCredentialsCreateProfile(ctx context.Context, q *storev1.TokenExchangeProfileCreateRequest) (*storev1.Result, error) {
	p, err := profileFromMsg(q.GetV())
	if err != nil || p == nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.GetTxId(), func(st store.Store) error { return st.ClientCredentials().CreateProfile(ctx, p, int(q.GetLimit())) }), nil
}

func (s *Server) profileResult(txID string, call func(store.ClientCredentials) (*store.TokenExchangeProfile, error)) *storev1.TokenExchangeProfileResult {
	out := &storev1.TokenExchangeProfileResult{}
	out.Error = errToPB(s.with(txID, func(st store.Store) error {
		p, err := call(st.ClientCredentials())
		if err == nil {
			out.Value = profileToMsg(p)
		}
		return err
	}))
	return out
}

func (s *Server) ClientCredentialsGetProfile(ctx context.Context, q *storev1.TokenExchangeProfileKeyRequest) (*storev1.TokenExchangeProfileResult, error) {
	return s.profileResult(q.GetTxId(), func(cc store.ClientCredentials) (*store.TokenExchangeProfile, error) {
		return cc.GetProfile(ctx, q.GetTid(), q.GetKey())
	}), nil
}

func (s *Server) ClientCredentialsGetProfileByType(ctx context.Context, q *storev1.TokenExchangeProfileKeyRequest) (*storev1.TokenExchangeProfileResult, error) {
	return s.profileResult(q.GetTxId(), func(cc store.ClientCredentials) (*store.TokenExchangeProfile, error) {
		return cc.GetProfileByType(ctx, q.GetTid(), q.GetKey())
	}), nil
}

func (s *Server) ClientCredentialsListProfiles(ctx context.Context, q *storev1.TokenExchangeProfileListRequest) (*storev1.TokenExchangeProfileListResult, error) {
	out := &storev1.TokenExchangeProfileListResult{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		ps, next, err := st.ClientCredentials().ListProfiles(ctx, q.GetTid(), q.GetFrom(), int(q.GetTake()))
		if err != nil {
			return err
		}
		for _, p := range ps {
			out.Values = append(out.Values, profileToMsg(p))
		}
		out.Next = next
		return nil
	}))
	return out, nil
}

func (s *Server) ClientCredentialsUpdateProfile(ctx context.Context, q *storev1.TokenExchangeProfileWrite) (*storev1.Result, error) {
	p, err := profileFromMsg(q.GetV())
	if err != nil || p == nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	return exec(s, q.GetTxId(), func(st store.Store) error { return st.ClientCredentials().UpdateProfile(ctx, p) }), nil
}

func (s *Server) ClientCredentialsDeleteProfile(ctx context.Context, q *storev1.TokenExchangeProfileKeyRequest) (*storev1.Result, error) {
	return exec(s, q.GetTxId(), func(st store.Store) error {
		return st.ClientCredentials().DeleteProfile(ctx, q.GetTid(), q.GetKey())
	}), nil
}

func (s *Server) ClientCredentialsProfilesForAction(ctx context.Context, q *storev1.TokenExchangeProfileKeyRequest) (*storev1.CountResult, error) {
	out := &storev1.CountResult{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		n, err := st.ClientCredentials().ProfilesForAction(ctx, q.GetTid(), q.GetKey())
		out.Count = int64(n)
		return err
	}))
	return out, nil
}
