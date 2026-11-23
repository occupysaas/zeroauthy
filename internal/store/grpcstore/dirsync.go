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

// Plan 37c Phase C: store.DirectorySync over the DirectoryCall RPC as
// methods named "DirectorySync.<Go method>", available when
// DirectoryCapabilities answers version 3. Field names must not clash with
// dirArgs, which the server decodes first.

const directorySyncPrefix = "DirectorySync."

type dsArgs struct {
	TenantID, ConnID string `json:",omitempty"`
	Provisioning     *store.DirectoryProvisioning
	SyncGroups       []store.SynchronizedGroup
	PageArg          store.Page
	Now              time.Time
	Lease            time.Duration
	Limit            int
}

type dsResult struct {
	Provisioning  *store.DirectoryProvisioning   `json:",omitempty"`
	Provisionings []*store.DirectoryProvisioning `json:",omitempty"`
	SyncGroups    []store.SynchronizedGroup      `json:",omitempty"`
	Total         int                            `json:",omitempty"`
}

type clientDirectorySync struct{ c *Client }

func (c *Client) DirectorySync() store.DirectorySync {
	if c.dsCap.v.Load() == 2 {
		return store.UnimplementedDirectorySync{}
	}
	return clientDirectorySync{c}
}

// CheckDirectorySyncSupport latches a definite scim.v1 version 3 answer.
func (c *Client) CheckDirectorySyncSupport(ctx context.Context) error {
	switch c.dsCap.v.Load() {
	case 1:
		return nil
	case 2:
		return store.ErrDirectorySyncUnavailable
	}
	v, err := c.rpc.DirectoryCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		err = rpcErr("scim.v1 capability", capabilityError(err, store.ErrDirectorySyncUnavailable))
	} else {
		err = errFromPB(v.GetError())
		if err == nil && v.GetVersion() < 3 {
			err = store.ErrDirectorySyncUnavailable
		}
	}
	if errors.Is(err, store.ErrDirectorySyncUnavailable) {
		c.dsCap.v.Store(2)
		return err
	}
	if err == nil {
		c.dsCap.v.CompareAndSwap(0, 1)
	}
	return err
}

func (c *Client) DirectorySyncSupported() bool {
	switch c.dsCap.v.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.CheckDirectorySyncSupport(ctx) == nil
}

func (d clientDirectorySync) call(ctx context.Context, method string, a dsArgs) (dsResult, error) {
	var out dsResult
	if err := d.c.CheckDirectorySyncSupport(ctx); err != nil {
		return out, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return out, err
	}
	r, err := d.c.rpc.DirectoryCall(ctx, &storev1.DirectoryCallRequest{TxId: d.c.txID, Method: directorySyncPrefix + method, Args: raw})
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
	if len(res.DirectorySync) > 0 {
		if err := json.Unmarshal(res.DirectorySync, &out); err != nil {
			return out, fmt.Errorf("DirectoryCall %s: decode result: %w", method, err)
		}
	}
	return out, nil
}

func (d clientDirectorySync) CreateProvisioning(ctx context.Context, p *store.DirectoryProvisioning) error {
	_, err := d.call(ctx, "CreateProvisioning", dsArgs{Provisioning: p})
	return err
}
func (d clientDirectorySync) GetProvisioning(ctx context.Context, tid, conn string) (*store.DirectoryProvisioning, error) {
	r, err := d.call(ctx, "GetProvisioning", dsArgs{TenantID: tid, ConnID: conn})
	return r.Provisioning, err
}
func (d clientDirectorySync) UpdateProvisioning(ctx context.Context, p *store.DirectoryProvisioning) error {
	_, err := d.call(ctx, "UpdateProvisioning", dsArgs{Provisioning: p})
	return err
}
func (d clientDirectorySync) DeleteProvisioning(ctx context.Context, tid, conn string) error {
	_, err := d.call(ctx, "DeleteProvisioning", dsArgs{TenantID: tid, ConnID: conn})
	return err
}
func (d clientDirectorySync) ListProvisionings(ctx context.Context, tid string, p store.Page) ([]*store.DirectoryProvisioning, int, error) {
	r, err := d.call(ctx, "ListProvisionings", dsArgs{TenantID: tid, PageArg: p})
	if err == nil && r.Provisionings == nil {
		r.Provisionings = []*store.DirectoryProvisioning{}
	}
	return r.Provisionings, r.Total, err
}
func (d clientDirectorySync) ClaimDue(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]*store.DirectoryProvisioning, error) {
	r, err := d.call(ctx, "ClaimDue", dsArgs{Now: now, Lease: lease, Limit: limit})
	return r.Provisionings, err
}
func (d clientDirectorySync) ReplaceGroups(ctx context.Context, tid, conn string, groups []store.SynchronizedGroup) error {
	_, err := d.call(ctx, "ReplaceGroups", dsArgs{TenantID: tid, ConnID: conn, SyncGroups: groups})
	return err
}
func (d clientDirectorySync) ListGroups(ctx context.Context, tid, conn string) ([]store.SynchronizedGroup, error) {
	r, err := d.call(ctx, "ListGroups", dsArgs{TenantID: tid, ConnID: conn})
	if err == nil && r.SyncGroups == nil {
		r.SyncGroups = []store.SynchronizedGroup{}
	}
	return r.SyncGroups, err
}

// serveDirectorySync runs one DirectorySync method on the server side and
// stores its encoded result in out.
func serveDirectorySync(ctx context.Context, ds store.DirectorySync, method string, raw []byte, out *json.RawMessage) error {
	var a dsArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return status.Error(codes.InvalidArgument, "DirectoryCall: malformed arguments")
	}
	if (method == "CreateProvisioning" || method == "UpdateProvisioning") && a.Provisioning == nil {
		return status.Error(codes.InvalidArgument, "DirectoryCall: missing provisioning")
	}
	var r dsResult
	var e error
	switch method {
	case "CreateProvisioning":
		e = ds.CreateProvisioning(ctx, a.Provisioning)
	case "GetProvisioning":
		r.Provisioning, e = ds.GetProvisioning(ctx, a.TenantID, a.ConnID)
	case "UpdateProvisioning":
		e = ds.UpdateProvisioning(ctx, a.Provisioning)
	case "DeleteProvisioning":
		e = ds.DeleteProvisioning(ctx, a.TenantID, a.ConnID)
	case "ListProvisionings":
		r.Provisionings, r.Total, e = ds.ListProvisionings(ctx, a.TenantID, a.PageArg)
	case "ClaimDue":
		r.Provisionings, e = ds.ClaimDue(ctx, a.Now, a.Lease, a.Limit)
	case "ReplaceGroups":
		e = ds.ReplaceGroups(ctx, a.TenantID, a.ConnID, a.SyncGroups)
	case "ListGroups":
		r.SyncGroups, e = ds.ListGroups(ctx, a.TenantID, a.ConnID)
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
