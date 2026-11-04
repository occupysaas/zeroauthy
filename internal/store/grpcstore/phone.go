package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
)

// phone.v1 carries store.Phone over the plugin protocol. It is negotiated by
// PhoneCapabilities, separately from every earlier capability, so a plugin
// that predates it keeps working and yields store.ErrPhoneUnavailable.

type clientPhone struct{ c *Client }

func (c *Client) Phone() store.Phone { return clientPhone{c} }

// A definitive unsupported answer is latched for the connection lifetime;
// transient transport errors are not.
func (c *Client) CheckPhoneSupport(ctx context.Context) error {
	if c.phoneCap.v.Load() == 2 {
		return store.ErrPhoneUnavailable
	}
	v, err := c.rpc.PhoneCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("Phone capability", capabilityError(err, store.ErrPhoneUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 1 {
			err = store.ErrPhoneUnavailable
		}
	}
	if errors.Is(err, store.ErrPhoneUnavailable) {
		c.phoneCap.v.Store(2)
	} else if err == nil {
		c.phoneCap.v.CompareAndSwap(0, 1)
	}
	if c.phoneCap.v.Load() == 2 {
		return store.ErrPhoneUnavailable
	}
	return err
}

func (c *Client) PhoneSupported() bool {
	switch c.phoneCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckPhoneSupport(ctx) == nil
}

func (s *Server) PhoneCapabilities(ctx context.Context, _ *storev1.PingRequest) (*storev1.EventsCapabilitiesResult, error) {
	if c, ok := s.st.(store.PhoneSupporter); ok {
		if err := c.CheckPhoneSupport(ctx); err != nil {
			return &storev1.EventsCapabilitiesResult{Error: errToPB(err)}, nil
		}
	}
	switch s.st.Phone().(type) {
	case store.UnimplementedPhone, *store.UnimplementedPhone:
		return &storev1.EventsCapabilitiesResult{}, nil
	}
	return &storev1.EventsCapabilitiesResult{Version: 1}, nil
}

// phoneCall probes the capability, runs one RPC and folds its outcome into
// the latch. call returns the RPC's error envelope.
func phoneCall(ctx context.Context, c *Client, op string, call func() (*storev1.Error, error)) error {
	if err := c.CheckPhoneSupport(ctx); err != nil {
		return err
	}
	e, err := call()
	if err != nil {
		err = capabilityError(err, store.ErrPhoneUnavailable)
		if errors.Is(err, store.ErrPhoneUnavailable) {
			c.phoneCap.v.Store(2)
		}
		return rpcErr(op, err)
	}
	err = errFromPB(e)
	if errors.Is(err, store.ErrPhoneUnavailable) {
		c.phoneCap.v.Store(2)
	}
	return err
}

// ---- codecs ----

func phoneProviderToPB(p *store.PhoneProvider) *storev1.PhoneProvider {
	if p == nil {
		return nil
	}
	return &storev1.PhoneProvider{TenantId: p.TenantID, Id: p.ID, Name: p.Name, Disabled: p.Disabled, Configuration: []byte(p.Configuration), SealedCredentials: p.SealedCredentials, CreatedAt: tsToPB(p.CreatedAt), UpdatedAt: tsToPB(p.UpdatedAt)}
}

func phoneProviderFromPB(p *storev1.PhoneProvider) (*store.PhoneProvider, error) {
	if p == nil {
		return nil, store.ErrInvalid
	}
	if err := checkTS(p.CreatedAt, p.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.PhoneProvider{TenantID: p.TenantId, ID: p.Id, Name: p.Name, Disabled: p.Disabled, Configuration: rawJSON(p.Configuration), SealedCredentials: optBytes(p.SealedCredentials), CreatedAt: tsFromPB(p.CreatedAt), UpdatedAt: tsFromPB(p.UpdatedAt)}, nil
}

func phoneTemplateToPB(t *store.PhoneTemplate) *storev1.PhoneTemplate {
	if t == nil {
		return nil
	}
	return &storev1.PhoneTemplate{TenantId: t.TenantID, Id: t.ID, Type: t.Type, Disabled: t.Disabled, Content: []byte(t.Content), Customizable: t.Customizable, CreatedAt: tsToPB(t.CreatedAt), UpdatedAt: tsToPB(t.UpdatedAt)}
}

func phoneTemplateFromPB(t *storev1.PhoneTemplate) (*store.PhoneTemplate, error) {
	if t == nil {
		return nil, store.ErrInvalid
	}
	if err := checkTS(t.CreatedAt, t.UpdatedAt); err != nil {
		return nil, err
	}
	return &store.PhoneTemplate{TenantID: t.TenantId, ID: t.Id, Type: t.Type, Disabled: t.Disabled, Content: rawJSON(t.Content), Customizable: t.Customizable, CreatedAt: tsFromPB(t.CreatedAt), UpdatedAt: tsFromPB(t.UpdatedAt)}, nil
}

func passwordlessCodeToPB(c *store.PasswordlessCode) *storev1.PasswordlessCode {
	if c == nil {
		return nil
	}
	return &storev1.PasswordlessCode{TenantId: c.TenantID, ConnectionId: c.ConnectionID, Identifier: c.Identifier, ClientId: c.ClientID, Kind: c.Kind, CodeHash: c.CodeHash, Request: []byte(c.Request), Attempts: int64(c.Attempts), ExpiresAt: tsToPB(c.ExpiresAt), CreatedAt: tsToPB(c.CreatedAt)}
}

func passwordlessCodeFromPB(c *storev1.PasswordlessCode) (*store.PasswordlessCode, error) {
	if c == nil {
		return nil, store.ErrInvalid
	}
	if err := checkTS(c.ExpiresAt, c.CreatedAt); err != nil {
		return nil, err
	}
	return &store.PasswordlessCode{TenantID: c.TenantId, ConnectionID: c.ConnectionId, Identifier: c.Identifier, ClientID: c.ClientId, Kind: c.Kind, CodeHash: c.CodeHash, Request: rawJSON(c.Request), Attempts: int(c.Attempts), ExpiresAt: tsFromPB(c.ExpiresAt), CreatedAt: tsFromPB(c.CreatedAt)}, nil
}

// rawJSON maps an empty wire value to a nil blob, like optBytes.
func rawJSON(b []byte) json.RawMessage { return json.RawMessage(optBytes(b)) }

// ---- client ----

func (o clientPhone) ListPhoneProviders(ctx context.Context, tid string) ([]store.PhoneProvider, error) {
	var r *storev1.PhoneListProvidersResponse
	if err := phoneCall(ctx, o.c, "PhoneListProviders", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneListProviders(ctx, &storev1.PhoneTenantRequest{TxId: o.c.txID, Tid: tid})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	out := make([]store.PhoneProvider, 0, len(r.Values))
	for _, v := range r.Values {
		p, err := phoneProviderFromPB(v)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, nil
}

func (o clientPhone) GetPhoneProvider(ctx context.Context, tid, id string) (*store.PhoneProvider, error) {
	var r *storev1.PhoneProviderResponse
	if err := phoneCall(ctx, o.c, "PhoneGetProvider", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneGetProvider(ctx, &storev1.PhoneIDRequest{TxId: o.c.txID, Tid: tid, Id: id})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return phoneProviderFromPB(r.Value)
}

func (o clientPhone) CreatePhoneProvider(ctx context.Context, p *store.PhoneProvider) error {
	if p == nil {
		return store.ErrInvalid
	}
	return phoneCall(ctx, o.c, "PhoneCreateProvider", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhoneCreateProvider(ctx, &storev1.PhoneProviderRequest{TxId: o.c.txID, V: phoneProviderToPB(p)})
		return r.GetError(), err
	})
}

func (o clientPhone) UpdatePhoneProvider(ctx context.Context, p *store.PhoneProvider) error {
	if p == nil {
		return store.ErrInvalid
	}
	return phoneCall(ctx, o.c, "PhoneUpdateProvider", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhoneUpdateProvider(ctx, &storev1.PhoneProviderRequest{TxId: o.c.txID, V: phoneProviderToPB(p)})
		return r.GetError(), err
	})
}

func (o clientPhone) DeletePhoneProvider(ctx context.Context, tid, id string) error {
	return phoneCall(ctx, o.c, "PhoneDeleteProvider", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhoneDeleteProvider(ctx, &storev1.PhoneIDRequest{TxId: o.c.txID, Tid: tid, Id: id})
		return r.GetError(), err
	})
}

func (o clientPhone) ListPhoneTemplates(ctx context.Context, tid string) ([]store.PhoneTemplate, error) {
	var r *storev1.PhoneListTemplatesResponse
	if err := phoneCall(ctx, o.c, "PhoneListTemplates", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneListTemplates(ctx, &storev1.PhoneTenantRequest{TxId: o.c.txID, Tid: tid})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	out := make([]store.PhoneTemplate, 0, len(r.Values))
	for _, v := range r.Values {
		t, err := phoneTemplateFromPB(v)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, nil
}

func (o clientPhone) GetPhoneTemplate(ctx context.Context, tid, id string) (*store.PhoneTemplate, error) {
	var r *storev1.PhoneTemplateResponse
	if err := phoneCall(ctx, o.c, "PhoneGetTemplate", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneGetTemplate(ctx, &storev1.PhoneIDRequest{TxId: o.c.txID, Tid: tid, Id: id})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return phoneTemplateFromPB(r.Value)
}

func (o clientPhone) PutPhoneTemplate(ctx context.Context, t *store.PhoneTemplate) error {
	if t == nil {
		return store.ErrInvalid
	}
	return phoneCall(ctx, o.c, "PhonePutTemplate", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhonePutTemplate(ctx, &storev1.PhoneTemplateRequest{TxId: o.c.txID, V: phoneTemplateToPB(t)})
		return r.GetError(), err
	})
}

func (o clientPhone) DeletePhoneTemplate(ctx context.Context, tid, id string) error {
	return phoneCall(ctx, o.c, "PhoneDeleteTemplate", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhoneDeleteTemplate(ctx, &storev1.PhoneIDRequest{TxId: o.c.txID, Tid: tid, Id: id})
		return r.GetError(), err
	})
}

func (o clientPhone) PutPasswordlessCode(ctx context.Context, c *store.PasswordlessCode) error {
	if c == nil {
		return store.ErrInvalid
	}
	return phoneCall(ctx, o.c, "PhonePutPasswordlessCode", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhonePutPasswordlessCode(ctx, &storev1.PhonePutCodeRequest{TxId: o.c.txID, V: passwordlessCodeToPB(c)})
		return r.GetError(), err
	})
}

func (o clientPhone) FailPasswordlessCode(ctx context.Context, tid, conn, ident, kind string, now time.Time) (int, error) {
	var r *storev1.PhoneFailCodeResponse
	if err := phoneCall(ctx, o.c, "PhoneFailPasswordlessCode", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneFailPasswordlessCode(ctx, &storev1.PhoneCodeKeyRequest{TxId: o.c.txID, Tid: tid, Connection: conn, Identifier: ident, Kind: kind, Now: tsToPB(now)})
		return r.GetError(), err
	}); err != nil {
		return 0, err
	}
	return int(r.Attempts), nil
}

func (o clientPhone) ConsumePasswordlessCode(ctx context.Context, tid, conn, ident, kind, hash string, maxAttempts int, now time.Time) (*store.PasswordlessCode, error) {
	var r *storev1.PhoneCodeResponse
	if err := phoneCall(ctx, o.c, "PhoneConsumePasswordlessCode", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneConsumePasswordlessCode(ctx, &storev1.PhoneConsumeCodeRequest{TxId: o.c.txID, Tid: tid, Connection: conn, Identifier: ident, Kind: kind, Hash: hash, MaxAttempts: int64(maxAttempts), Now: tsToPB(now)})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return passwordlessCodeFromPB(r.Value)
}

func (o clientPhone) PeekPasswordlessLink(ctx context.Context, tid, hash string, now time.Time) (*store.PasswordlessCode, error) {
	var r *storev1.PhoneCodeResponse
	if err := phoneCall(ctx, o.c, "PhonePeekPasswordlessLink", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhonePeekPasswordlessLink(ctx, &storev1.PhonePeekLinkRequest{TxId: o.c.txID, Tid: tid, Hash: hash, Now: tsToPB(now)})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	return passwordlessCodeFromPB(r.Value)
}

func (o clientPhone) FindUsersByPhone(ctx context.Context, tid, connection, e164 string) ([]store.User, error) {
	var r *storev1.PhoneFindUsersResponse
	if err := phoneCall(ctx, o.c, "PhoneFindUsersByPhone", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhoneFindUsersByPhone(ctx, &storev1.PhoneFindUsersRequest{TxId: o.c.txID, Tid: tid, Connection: connection, E164: e164})
		return r.GetError(), err
	}); err != nil {
		return nil, err
	}
	out := make([]store.User, 0, len(r.Values))
	for _, v := range r.Values {
		u, err := userFromPB(v)
		if err != nil {
			return nil, err
		}
		if u != nil {
			out = append(out, *u)
		}
	}
	return out, nil
}

func (o clientPhone) PurgePhone(ctx context.Context, before time.Time, limit int) (int, error) {
	var r *storev1.PhoneCountResponse
	if err := phoneCall(ctx, o.c, "PhonePurge", func() (*storev1.Error, error) {
		var err error
		r, err = o.c.rpc.PhonePurge(ctx, &storev1.PhonePurgeRequest{TxId: o.c.txID, Before: tsToPB(before), Limit: int64(limit)})
		return r.GetError(), err
	}); err != nil {
		return 0, err
	}
	return int(r.Count), nil
}

func (o clientPhone) DeleteTenantPhone(ctx context.Context, tid string) error {
	return phoneCall(ctx, o.c, "PhoneDeleteTenant", func() (*storev1.Error, error) {
		r, err := o.c.rpc.PhoneDeleteTenant(ctx, &storev1.PhoneTenantRequest{TxId: o.c.txID, Tid: tid})
		return r.GetError(), err
	})
}

// ---- server ----

func (s *Server) PhoneListProviders(ctx context.Context, q *storev1.PhoneTenantRequest) (*storev1.PhoneListProvidersResponse, error) {
	out := &storev1.PhoneListProvidersResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.Phone().ListPhoneProviders(ctx, q.GetTid())
		for i := range v {
			out.Values = append(out.Values, phoneProviderToPB(&v[i]))
		}
		return err
	}))
	return out, nil
}

func (s *Server) PhoneGetProvider(ctx context.Context, q *storev1.PhoneIDRequest) (*storev1.PhoneProviderResponse, error) {
	out := &storev1.PhoneProviderResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.Phone().GetPhoneProvider(ctx, q.GetTid(), q.GetId())
		out.Value = phoneProviderToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) PhoneCreateProvider(ctx context.Context, q *storev1.PhoneProviderRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), q.GetV() == nil, func(st store.Store) error {
		p, err := phoneProviderFromPB(q.V)
		if err != nil {
			return err
		}
		return st.Phone().CreatePhoneProvider(ctx, p)
	}), nil
}

func (s *Server) PhoneUpdateProvider(ctx context.Context, q *storev1.PhoneProviderRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), q.GetV() == nil, func(st store.Store) error {
		p, err := phoneProviderFromPB(q.V)
		if err != nil {
			return err
		}
		return st.Phone().UpdatePhoneProvider(ctx, p)
	}), nil
}

func (s *Server) PhoneDeleteProvider(ctx context.Context, q *storev1.PhoneIDRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), false, func(st store.Store) error {
		return st.Phone().DeletePhoneProvider(ctx, q.GetTid(), q.GetId())
	}), nil
}

func (s *Server) PhoneListTemplates(ctx context.Context, q *storev1.PhoneTenantRequest) (*storev1.PhoneListTemplatesResponse, error) {
	out := &storev1.PhoneListTemplatesResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.Phone().ListPhoneTemplates(ctx, q.GetTid())
		for i := range v {
			out.Values = append(out.Values, phoneTemplateToPB(&v[i]))
		}
		return err
	}))
	return out, nil
}

func (s *Server) PhoneGetTemplate(ctx context.Context, q *storev1.PhoneIDRequest) (*storev1.PhoneTemplateResponse, error) {
	out := &storev1.PhoneTemplateResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.Phone().GetPhoneTemplate(ctx, q.GetTid(), q.GetId())
		out.Value = phoneTemplateToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) PhonePutTemplate(ctx context.Context, q *storev1.PhoneTemplateRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), q.GetV() == nil, func(st store.Store) error {
		t, err := phoneTemplateFromPB(q.V)
		if err != nil {
			return err
		}
		return st.Phone().PutPhoneTemplate(ctx, t)
	}), nil
}

func (s *Server) PhoneDeleteTemplate(ctx context.Context, q *storev1.PhoneIDRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), false, func(st store.Store) error {
		return st.Phone().DeletePhoneTemplate(ctx, q.GetTid(), q.GetId())
	}), nil
}

func (s *Server) PhonePutPasswordlessCode(ctx context.Context, q *storev1.PhonePutCodeRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), q.GetV() == nil, func(st store.Store) error {
		c, err := passwordlessCodeFromPB(q.V)
		if err != nil {
			return err
		}
		return st.Phone().PutPasswordlessCode(ctx, c)
	}), nil
}

func (s *Server) PhoneFailPasswordlessCode(ctx context.Context, q *storev1.PhoneCodeKeyRequest) (*storev1.PhoneFailCodeResponse, error) {
	out := &storev1.PhoneFailCodeResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.Now); err != nil {
			return store.ErrInvalid
		}
		n, err := st.Phone().FailPasswordlessCode(ctx, q.GetTid(), q.GetConnection(), q.GetIdentifier(), q.GetKind(), tsFromPB(q.Now))
		out.Attempts = int64(n)
		return err
	}))
	return out, nil
}

func (s *Server) PhoneConsumePasswordlessCode(ctx context.Context, q *storev1.PhoneConsumeCodeRequest) (*storev1.PhoneCodeResponse, error) {
	out := &storev1.PhoneCodeResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.Now); err != nil {
			return store.ErrInvalid
		}
		v, err := st.Phone().ConsumePasswordlessCode(ctx, q.GetTid(), q.GetConnection(), q.GetIdentifier(), q.GetKind(), q.GetHash(), int(q.GetMaxAttempts()), tsFromPB(q.Now))
		out.Value = passwordlessCodeToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) PhonePeekPasswordlessLink(ctx context.Context, q *storev1.PhonePeekLinkRequest) (*storev1.PhoneCodeResponse, error) {
	out := &storev1.PhoneCodeResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.Now); err != nil {
			return store.ErrInvalid
		}
		v, err := st.Phone().PeekPasswordlessLink(ctx, q.GetTid(), q.GetHash(), tsFromPB(q.Now))
		out.Value = passwordlessCodeToPB(v)
		return err
	}))
	return out, nil
}

func (s *Server) PhoneFindUsersByPhone(ctx context.Context, q *storev1.PhoneFindUsersRequest) (*storev1.PhoneFindUsersResponse, error) {
	out := &storev1.PhoneFindUsersResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		v, err := st.Phone().FindUsersByPhone(ctx, q.GetTid(), q.GetConnection(), q.GetE164())
		if err != nil {
			return err
		}
		for i := range v {
			pb, err := userToPB(&v[i])
			if err != nil {
				return err
			}
			out.Values = append(out.Values, pb)
		}
		return nil
	}))
	return out, nil
}

func (s *Server) PhonePurge(ctx context.Context, q *storev1.PhonePurgeRequest) (*storev1.PhoneCountResponse, error) {
	out := &storev1.PhoneCountResponse{}
	out.Error = errToPB(s.with(q.GetTxId(), func(st store.Store) error {
		if err := checkTS(q.Before); err != nil {
			return store.ErrInvalid
		}
		n, err := st.Phone().PurgePhone(ctx, tsFromPB(q.Before), int(q.GetLimit()))
		out.Count = int64(n)
		return err
	}))
	return out, nil
}

func (s *Server) PhoneDeleteTenant(ctx context.Context, q *storev1.PhoneTenantRequest) (*storev1.PhoneErrorResponse, error) {
	return s.phoneWrite(q.GetTxId(), false, func(st store.Store) error {
		return st.Phone().DeleteTenantPhone(ctx, q.GetTid())
	}), nil
}

// phoneWrite runs a write; a missing message is an invalid request.
func (s *Server) phoneWrite(txID string, missing bool, f func(store.Store) error) *storev1.PhoneErrorResponse {
	if missing {
		return &storev1.PhoneErrorResponse{Error: errToPB(store.ErrInvalid)}
	}
	return &storev1.PhoneErrorResponse{Error: errToPB(s.with(txID, f))}
}
