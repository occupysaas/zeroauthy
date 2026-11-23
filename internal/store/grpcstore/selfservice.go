package grpcstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Plan 37c Phase B: store.SelfService over the DirectoryCall RPC (field
// names must not clash with dirArgs, which the server decodes first), as methods
// named "SelfService.<Go method>", available when DirectoryCapabilities
// answers version 2. args and the result are the JSON of ssArgs and
// ssResult.

const selfServicePrefix = "SelfService."

type ssArgs struct {
	TenantID, ID, ProfileID, Hash, Language, TextPage, ConnID string `json:",omitempty"`
	Profile                                                   *store.SelfServiceProfile
	Ticket                                                    *store.SSOTicket
	ConnectionProfile                                         *store.ConnectionProfile
	Text                                                      json.RawMessage `json:",omitempty"`
	PageArg                                                   store.Page
	Now                                                       time.Time
}

type ssResult struct {
	Profile            *store.SelfServiceProfile   `json:",omitempty"`
	Profiles           []*store.SelfServiceProfile `json:",omitempty"`
	Ticket             *store.SSOTicket            `json:",omitempty"`
	ConnectionProfile  *store.ConnectionProfile    `json:",omitempty"`
	ConnectionProfiles []*store.ConnectionProfile  `json:",omitempty"`
	Text               json.RawMessage             `json:",omitempty"`
	Total              int                         `json:",omitempty"`
}

type clientSelfService struct{ c *Client }

func (c *Client) SelfService() store.SelfService {
	if c.ssCap.v.Load() == 2 {
		return store.UnimplementedSelfService{}
	}
	return clientSelfService{c}
}

// CheckSelfServiceSupport latches a definite scim.v1 version 2 answer.
func (c *Client) CheckSelfServiceSupport(ctx context.Context) error {
	switch c.ssCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrSelfServiceUnavailable
	}
	v, err := c.rpc.DirectoryCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("scim.v1 capability", capabilityError(err, store.ErrSelfServiceUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 2 {
			err = store.ErrSelfServiceUnavailable
		}
	}
	if errors.Is(err, store.ErrSelfServiceUnavailable) {
		c.ssCap.v.Store(2)
		return err
	}
	if err == nil {
		c.ssCap.v.CompareAndSwap(0, 1)
	}
	return err
}

func (c *Client) SelfServiceSupported() bool {
	switch c.ssCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckSelfServiceSupport(ctx) == nil
}

func (d clientSelfService) call(ctx context.Context, method string, a ssArgs) (ssResult, error) {
	var out ssResult
	if err := d.c.CheckSelfServiceSupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := d.c.rpc.DirectoryCall(ctx, &storev1.DirectoryCallRequest{TxId: d.c.txID, Method: selfServicePrefix + method, Args: raw})
	if err != nil {
		return out, rpcErr("DirectoryCall "+method, err)
	}
	if e := errFromPB(r.GetError()); e != nil {
		return out, e
	}
	var res dirResult
	if len(r.GetResult()) > 0 {
		if err := json.Unmarshal(r.GetResult(), &res); err != nil {
			return out, fmt.Errorf("DirectoryCall %s: decode result: %w", method, err)
		}
	}
	if len(res.SelfService) > 0 {
		if err := json.Unmarshal(res.SelfService, &out); err != nil {
			return out, fmt.Errorf("DirectoryCall %s: decode result: %w", method, err)
		}
	}
	return out, nil
}

func (d clientSelfService) CreateProfile(ctx context.Context, p *store.SelfServiceProfile) error {
	_, err := d.call(ctx, "CreateProfile", ssArgs{Profile: p})
	return err
}
func (d clientSelfService) GetProfile(ctx context.Context, tid, id string) (*store.SelfServiceProfile, error) {
	r, err := d.call(ctx, "GetProfile", ssArgs{TenantID: tid, ID: id})
	return r.Profile, err
}
func (d clientSelfService) UpdateProfile(ctx context.Context, p *store.SelfServiceProfile) error {
	_, err := d.call(ctx, "UpdateProfile", ssArgs{Profile: p})
	return err
}
func (d clientSelfService) DeleteProfile(ctx context.Context, tid, id string) error {
	_, err := d.call(ctx, "DeleteProfile", ssArgs{TenantID: tid, ID: id})
	return err
}
func (d clientSelfService) ListProfiles(ctx context.Context, tid string, p store.Page) ([]*store.SelfServiceProfile, int, error) {
	r, err := d.call(ctx, "ListProfiles", ssArgs{TenantID: tid, PageArg: p})
	if err == nil && r.Profiles == nil {
		r.Profiles = []*store.SelfServiceProfile{}
	}
	return r.Profiles, r.Total, err
}
func (d clientSelfService) GetCustomText(ctx context.Context, tid, pid, lang, page string) (json.RawMessage, error) {
	r, err := d.call(ctx, "GetCustomText", ssArgs{TenantID: tid, ProfileID: pid, Language: lang, TextPage: page})
	return r.Text, err
}
func (d clientSelfService) SetCustomText(ctx context.Context, tid, pid, lang, page string, text json.RawMessage) error {
	_, err := d.call(ctx, "SetCustomText", ssArgs{TenantID: tid, ProfileID: pid, Language: lang, TextPage: page, Text: text})
	return err
}
func (d clientSelfService) CreateTicket(ctx context.Context, t *store.SSOTicket) error {
	_, err := d.call(ctx, "CreateTicket", ssArgs{Ticket: t})
	return err
}
func (d clientSelfService) GetTicketByHash(ctx context.Context, tid, hash string) (*store.SSOTicket, error) {
	r, err := d.call(ctx, "GetTicketByHash", ssArgs{TenantID: tid, Hash: hash})
	return r.Ticket, err
}
func (d clientSelfService) RevokeTicket(ctx context.Context, tid, pid, id string, now time.Time) error {
	_, err := d.call(ctx, "RevokeTicket", ssArgs{TenantID: tid, ProfileID: pid, ID: id, Now: now})
	return err
}
func (d clientSelfService) UseTicket(ctx context.Context, tid, id string, now time.Time) error {
	_, err := d.call(ctx, "UseTicket", ssArgs{TenantID: tid, ID: id, Now: now})
	return err
}
func (d clientSelfService) BindTicketConnection(ctx context.Context, tid, id, conn string) error {
	_, err := d.call(ctx, "BindTicketConnection", ssArgs{TenantID: tid, ID: id, ConnID: conn})
	return err
}
func (d clientSelfService) CreateConnectionProfile(ctx context.Context, p *store.ConnectionProfile) error {
	_, err := d.call(ctx, "CreateConnectionProfile", ssArgs{ConnectionProfile: p})
	return err
}
func (d clientSelfService) GetConnectionProfile(ctx context.Context, tid, id string) (*store.ConnectionProfile, error) {
	r, err := d.call(ctx, "GetConnectionProfile", ssArgs{TenantID: tid, ID: id})
	return r.ConnectionProfile, err
}
func (d clientSelfService) UpdateConnectionProfile(ctx context.Context, p *store.ConnectionProfile) error {
	_, err := d.call(ctx, "UpdateConnectionProfile", ssArgs{ConnectionProfile: p})
	return err
}
func (d clientSelfService) DeleteConnectionProfile(ctx context.Context, tid, id string) error {
	_, err := d.call(ctx, "DeleteConnectionProfile", ssArgs{TenantID: tid, ID: id})
	return err
}
func (d clientSelfService) ListConnectionProfiles(ctx context.Context, tid string, p store.Page) ([]*store.ConnectionProfile, int, error) {
	r, err := d.call(ctx, "ListConnectionProfiles", ssArgs{TenantID: tid, PageArg: p})
	if err == nil && r.ConnectionProfiles == nil {
		r.ConnectionProfiles = []*store.ConnectionProfile{}
	}
	return r.ConnectionProfiles, r.Total, err
}

// serveSelfService runs one SelfService method on the server side and
// stores its encoded result in out.
func serveSelfService(ctx context.Context, ss store.SelfService, method string, raw []byte, out *json.RawMessage) error {
	var a ssArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return status.Error(codes.InvalidArgument, "DirectoryCall: malformed arguments")
	}
	var r ssResult
	var e error
	switch method {
	case "CreateProfile":
		e = ss.CreateProfile(ctx, a.Profile)
	case "GetProfile":
		r.Profile, e = ss.GetProfile(ctx, a.TenantID, a.ID)
	case "UpdateProfile":
		e = ss.UpdateProfile(ctx, a.Profile)
	case "DeleteProfile":
		e = ss.DeleteProfile(ctx, a.TenantID, a.ID)
	case "ListProfiles":
		r.Profiles, r.Total, e = ss.ListProfiles(ctx, a.TenantID, a.PageArg)
	case "GetCustomText":
		r.Text, e = ss.GetCustomText(ctx, a.TenantID, a.ProfileID, a.Language, a.TextPage)
	case "SetCustomText":
		e = ss.SetCustomText(ctx, a.TenantID, a.ProfileID, a.Language, a.TextPage, a.Text)
	case "CreateTicket":
		e = ss.CreateTicket(ctx, a.Ticket)
	case "GetTicketByHash":
		r.Ticket, e = ss.GetTicketByHash(ctx, a.TenantID, a.Hash)
	case "RevokeTicket":
		e = ss.RevokeTicket(ctx, a.TenantID, a.ProfileID, a.ID, a.Now)
	case "UseTicket":
		e = ss.UseTicket(ctx, a.TenantID, a.ID, a.Now)
	case "BindTicketConnection":
		e = ss.BindTicketConnection(ctx, a.TenantID, a.ID, a.ConnID)
	case "CreateConnectionProfile":
		e = ss.CreateConnectionProfile(ctx, a.ConnectionProfile)
	case "GetConnectionProfile":
		r.ConnectionProfile, e = ss.GetConnectionProfile(ctx, a.TenantID, a.ID)
	case "UpdateConnectionProfile":
		e = ss.UpdateConnectionProfile(ctx, a.ConnectionProfile)
	case "DeleteConnectionProfile":
		e = ss.DeleteConnectionProfile(ctx, a.TenantID, a.ID)
	case "ListConnectionProfiles":
		r.ConnectionProfiles, r.Total, e = ss.ListConnectionProfiles(ctx, a.TenantID, a.PageArg)
	default:
		return status.Error(codes.Unimplemented, "DirectoryCall: unknown method")
	}
	enc, err := json.Marshal(r)
	if err != nil {
		return err
	}
	*out = enc
	return e
}
