package grpcstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/actionsrules"
	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/grpc"
)

// artifactChunk is the payload size of one streamed artifact message, well
// under gRPC's 4 MB default message limit.
const artifactChunk = 256 << 10

// maxArtifact is the store's artifact limit, shared with the repositories.
func maxArtifact() int64 { return int64(actionsrules.Inventory().Limits["artifact_bytes_max"]) }

type clientActions struct{ c *Client }

// Actions returns the plugin-backed repository. A plugin without the RPCs
// yields store.ErrActionsUnavailable, never an empty registry.
func (c *Client) Actions() store.Actions { return clientActions{c} }

// CheckActionsSupport reports whether the plugin serves the Actions RPCs.
func (c *Client) CheckActionsSupport(ctx context.Context) error {
	v, err := c.rpc.ActionsCapabilities(ctx, &storev1.PingRequest{})
	if err != nil {
		return fmt.Errorf("storage plugin Actions: %w", capabilityError(err, store.ErrActionsUnavailable))
	}
	if err := errFromPB(v.GetError()); err != nil {
		return err
	}
	if v.Version < 1 {
		return store.ErrActionsUnavailable
	}
	return nil
}

func (s *Server) ActionsCapabilities(context.Context, *storev1.PingRequest) (*storev1.ActionsCapabilitiesResult, error) {
	return &storev1.ActionsCapabilitiesResult{Version: 1}, nil
}

func depsToPB(d []store.Dependency) []*storev1.ActionDependency {
	out := make([]*storev1.ActionDependency, 0, len(d))
	for _, x := range d {
		out = append(out, &storev1.ActionDependency{Name: x.Name, Version: x.Version})
	}
	return out
}

func depsFromPB(d []*storev1.ActionDependency) []store.Dependency {
	if d == nil {
		return nil
	}
	out := make([]store.Dependency, 0, len(d))
	for _, x := range d {
		out = append(out, store.Dependency{Name: x.GetName(), Version: x.GetVersion()})
	}
	return out
}

func secretsToPB(s []store.ActionSecret) []*storev1.ActionSecretMsg {
	out := make([]*storev1.ActionSecretMsg, 0, len(s))
	for _, x := range s {
		out = append(out, &storev1.ActionSecretMsg{Name: x.Name, Sealed: x.Sealed, UpdatedAt: tsToPB(x.UpdatedAt)})
	}
	return out
}

func secretsFromPB(s []*storev1.ActionSecretMsg) []store.ActionSecret {
	if s == nil {
		return nil
	}
	out := make([]store.ActionSecret, 0, len(s))
	for _, x := range s {
		out = append(out, store.ActionSecret{Name: x.GetName(), Sealed: x.GetSealed(), UpdatedAt: tsFromPB(x.GetUpdatedAt())})
	}
	return out
}

func actionToPB(a *store.Action) *storev1.ActionMsg {
	if a == nil {
		return nil
	}
	return &storev1.ActionMsg{TenantId: a.TenantID, Id: a.ID, Name: a.Name, Trigger: a.Trigger, Runtime: a.Runtime, Code: a.Code,
		Dependencies: depsToPB(a.Dependencies), Secrets: secretsToPB(a.Secrets), DraftBuildId: a.DraftBuildID,
		DeployedVersionId: a.DeployedVersionID, CreatedAt: tsToPB(a.CreatedAt), UpdatedAt: tsToPB(a.UpdatedAt)}
}

func actionFromPB(a *storev1.ActionMsg) *store.Action {
	if a == nil {
		return nil
	}
	return &store.Action{TenantID: a.TenantId, ID: a.Id, Name: a.Name, Trigger: a.Trigger, Runtime: a.Runtime, Code: a.Code,
		Dependencies: depsFromPB(a.Dependencies), Secrets: secretsFromPB(a.Secrets), DraftBuildID: a.DraftBuildId,
		DeployedVersionID: a.DeployedVersionId, CreatedAt: tsFromPB(a.CreatedAt), UpdatedAt: tsFromPB(a.UpdatedAt)}
}

func versionToPB(v *store.ActionVersion) *storev1.ActionVersionMsg {
	if v == nil {
		return nil
	}
	return &storev1.ActionVersionMsg{TenantId: v.TenantID, ActionId: v.ActionID, Id: v.ID, Number: int64(v.Number), Code: v.Code,
		Runtime: v.Runtime, BuildId: v.BuildID, Dependencies: depsToPB(v.Dependencies), Secrets: secretsToPB(v.Secrets), CreatedAt: tsToPB(v.CreatedAt)}
}

func versionFromPB(v *storev1.ActionVersionMsg) *store.ActionVersion {
	if v == nil {
		return nil
	}
	return &store.ActionVersion{TenantID: v.TenantId, ActionID: v.ActionId, ID: v.Id, Number: int(v.Number), Code: v.Code,
		Runtime: v.Runtime, BuildID: v.BuildId, Dependencies: depsFromPB(v.Dependencies), Secrets: secretsFromPB(v.Secrets), CreatedAt: tsFromPB(v.CreatedAt)}
}

func buildToPB(b *store.Build) *storev1.ActionBuildMsg {
	if b == nil {
		return nil
	}
	return &storev1.ActionBuildMsg{TenantId: b.TenantID, Id: b.ID, Status: string(b.Status), Requested: depsToPB(b.Requested),
		Resolved: depsToPB(b.Resolved), Errors: b.Errors, ArtifactSha256: b.ArtifactSHA256, BuiltAt: tsToPB(b.BuiltAt)}
}

func buildFromPB(b *storev1.ActionBuildMsg) *store.Build {
	if b == nil {
		return nil
	}
	return &store.Build{TenantID: b.TenantId, ID: b.Id, Status: store.BuildStatus(b.Status), Requested: depsFromPB(b.Requested),
		Resolved: depsFromPB(b.Resolved), Errors: b.Errors, ArtifactSHA256: b.ArtifactSha256, BuiltAt: tsFromPB(b.BuiltAt)}
}

func bindingToPB(b store.Binding) *storev1.ActionBindingMsg {
	return &storev1.ActionBindingMsg{TenantId: b.TenantID, Trigger: b.Trigger, Id: b.ID, ActionId: b.ActionID,
		DisplayName: b.DisplayName, CreatedAt: tsToPB(b.CreatedAt), UpdatedAt: tsToPB(b.UpdatedAt)}
}

func bindingFromPB(b *storev1.ActionBindingMsg) store.Binding {
	return store.Binding{TenantID: b.GetTenantId(), Trigger: b.GetTrigger(), ID: b.GetId(), ActionID: b.GetActionId(),
		DisplayName: b.GetDisplayName(), CreatedAt: tsFromPB(b.GetCreatedAt()), UpdatedAt: tsFromPB(b.GetUpdatedAt())}
}

func boundToPB(v []store.BoundVersion) []*storev1.ActionBoundMsg {
	out := make([]*storev1.ActionBoundMsg, 0, len(v))
	for _, x := range v {
		out = append(out, &storev1.ActionBoundMsg{Binding: bindingToPB(x.Binding), Action: actionToPB(&x.Action), Version: versionToPB(&x.Version)})
	}
	return out
}

func boundFromPB(v []*storev1.ActionBoundMsg) []store.BoundVersion {
	out := make([]store.BoundVersion, 0, len(v))
	for _, x := range v {
		bv := store.BoundVersion{Binding: bindingFromPB(x.GetBinding())}
		if a := actionFromPB(x.GetAction()); a != nil {
			bv.Action = *a
		}
		if ver := versionFromPB(x.GetVersion()); ver != nil {
			bv.Version = *ver
		}
		out = append(out, bv)
	}
	return out
}

func executionToPB(e *store.Execution) *storev1.ActionExecutionMsg {
	if e == nil {
		return nil
	}
	pb := &storev1.ActionExecutionMsg{TenantId: e.TenantID, Id: e.ID, Trigger: e.Trigger, Status: e.Status,
		CreatedAt: tsToPB(e.CreatedAt), UpdatedAt: tsToPB(e.UpdatedAt)}
	for _, r := range e.Results {
		pb.Results = append(pb.Results, &storev1.ActionExecutionResultMsg{ActionName: r.ActionName, ErrorId: r.ErrorID,
			ErrorMsg: r.ErrorMsg, StartedAt: tsToPB(r.StartedAt), EndedAt: tsToPB(r.EndedAt)})
	}
	return pb
}

func executionFromPB(e *storev1.ActionExecutionMsg) *store.Execution {
	if e == nil {
		return nil
	}
	out := &store.Execution{TenantID: e.TenantId, ID: e.Id, Trigger: e.Trigger, Status: e.Status,
		CreatedAt: tsFromPB(e.CreatedAt), UpdatedAt: tsFromPB(e.UpdatedAt)}
	for _, r := range e.Results {
		out.Results = append(out.Results, store.ExecutionResult{ActionName: r.GetActionName(), ErrorID: r.GetErrorId(),
			ErrorMsg: r.GetErrorMsg(), StartedAt: tsFromPB(r.GetStartedAt()), EndedAt: tsFromPB(r.GetEndedAt())})
	}
	return out
}

func continueToPB(c *store.ContinueState) *storev1.ActionContinueMsg {
	if c == nil {
		return nil
	}
	return &storev1.ActionContinueMsg{TenantId: c.TenantID, StateHash: c.StateHash, SessionId: c.SessionID, Sealed: c.Sealed,
		ExpiresAt: tsToPB(c.ExpiresAt), CreatedAt: tsToPB(c.CreatedAt)}
}

func continueFromPB(c *storev1.ActionContinueMsg) *store.ContinueState {
	if c == nil {
		return nil
	}
	return &store.ContinueState{TenantID: c.TenantId, StateHash: c.StateHash, SessionID: c.SessionId, Sealed: c.Sealed,
		ExpiresAt: tsFromPB(c.ExpiresAt), CreatedAt: tsFromPB(c.CreatedAt)}
}

// actionsErr maps an Unimplemented status to store.ErrActionsUnavailable.
func actionsErr(op string, err error) error {
	return fmt.Errorf("storage plugin Actions: %s: %w", op, capabilityError(err, store.ErrActionsUnavailable))
}

func (r clientActions) call(op string, f func() (*storev1.ActionsResponse, error)) (*storev1.ActionsResponse, error) {
	v, err := f()
	if err != nil {
		return nil, actionsErr(op, err)
	}
	if e := errFromPB(v.GetError()); e != nil {
		return nil, e
	}
	return v, nil
}

func (r clientActions) req(tid string) *storev1.ActionsRequest {
	return &storev1.ActionsRequest{TxId: r.c.txID, TenantId: tid}
}

// actionsServe runs one unary handler against the backing store.
func (srv *Server) actionsServe(q *storev1.ActionsRequest, f func(store.Actions, *storev1.ActionsResponse) error) *storev1.ActionsResponse {
	out := &storev1.ActionsResponse{}
	err := srv.with(q.TxId, func(s store.Store) error { return f(s.Actions(), out) })
	out.Error = errToPB(err)
	return out
}

func (r clientActions) CreateAction(ctx context.Context, a *store.Action) error {
	q := r.req(a.TenantID)
	q.Action = actionToPB(a)
	_, err := r.call("CreateAction", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsCreateAction(ctx, q) })
	return err
}
func (srv *Server) ActionsCreateAction(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.CreateAction(ctx, actionFromPB(q.Action))
	}), nil
}

func (r clientActions) GetAction(ctx context.Context, tid, id string) (*store.Action, error) {
	q := r.req(tid)
	q.Id = id
	v, err := r.call("GetAction", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetAction(ctx, q) })
	if err != nil {
		return nil, err
	}
	return actionFromPB(v.Action), nil
}
func (srv *Server) ActionsGetAction(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetAction(ctx, q.TenantId, q.Id)
		o.Action = actionToPB(v)
		return err
	}), nil
}

func (r clientActions) GetActionByName(ctx context.Context, tid, name string) (*store.Action, error) {
	q := r.req(tid)
	q.Name = name
	v, err := r.call("GetActionByName", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetActionByName(ctx, q) })
	if err != nil {
		return nil, err
	}
	return actionFromPB(v.Action), nil
}
func (srv *Server) ActionsGetActionByName(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetActionByName(ctx, q.TenantId, q.Name)
		o.Action = actionToPB(v)
		return err
	}), nil
}

func (r clientActions) UpdateAction(ctx context.Context, a *store.Action) error {
	q := r.req(a.TenantID)
	q.Action = actionToPB(a)
	_, err := r.call("UpdateAction", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsUpdateAction(ctx, q) })
	return err
}
func (srv *Server) ActionsUpdateAction(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.UpdateAction(ctx, actionFromPB(q.Action))
	}), nil
}

func (r clientActions) DeleteAction(ctx context.Context, tid, id string, force bool) error {
	q := r.req(tid)
	q.Id, q.Force = id, force
	_, err := r.call("DeleteAction", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsDeleteAction(ctx, q) })
	return err
}
func (srv *Server) ActionsDeleteAction(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.DeleteAction(ctx, q.TenantId, q.Id, q.Force)
	}), nil
}

func (r clientActions) ListActions(ctx context.Context, tid string, f store.ActionFilter) (store.Paged[store.Action], error) {
	q := r.req(tid)
	q.Trigger, q.Page, q.PerPage = f.Trigger, int64(f.Page), int64(f.PerPage)
	out := store.Paged[store.Action]{Items: []store.Action{}}
	v, err := r.call("ListActions", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsListActions(ctx, q) })
	if err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	for _, x := range v.Actions {
		if x == nil {
			return out, fmt.Errorf("%w: plugin returned a nil Action", store.ErrInvalid)
		}
		out.Items = append(out.Items, *actionFromPB(x))
	}
	return out, nil
}
func (srv *Server) ActionsListActions(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		p, err := a.ListActions(ctx, q.TenantId, store.ActionFilter{Trigger: q.Trigger, PageRequest: store.PageRequest{Page: int(q.Page), PerPage: int(q.PerPage)}})
		o.Total = int64(p.Total)
		for i := range p.Items {
			o.Actions = append(o.Actions, actionToPB(&p.Items[i]))
		}
		return err
	}), nil
}

func (r clientActions) Deploy(ctx context.Context, tid, actionID, fromVersionID string) (*store.ActionVersion, error) {
	q := r.req(tid)
	q.ActionId, q.VersionId = actionID, fromVersionID
	v, err := r.call("Deploy", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsDeploy(ctx, q) })
	if err != nil {
		return nil, err
	}
	return versionFromPB(v.Version), nil
}
func (srv *Server) ActionsDeploy(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.Deploy(ctx, q.TenantId, q.ActionId, q.VersionId)
		o.Version = versionToPB(v)
		return err
	}), nil
}

func (r clientActions) GetVersion(ctx context.Context, tid, actionID, versionID string) (*store.ActionVersion, error) {
	q := r.req(tid)
	q.ActionId, q.VersionId = actionID, versionID
	v, err := r.call("GetVersion", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetVersion(ctx, q) })
	if err != nil {
		return nil, err
	}
	return versionFromPB(v.Version), nil
}
func (srv *Server) ActionsGetVersion(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetVersion(ctx, q.TenantId, q.ActionId, q.VersionId)
		o.Version = versionToPB(v)
		return err
	}), nil
}

func (r clientActions) ListVersions(ctx context.Context, tid, actionID string, p store.PageRequest) (store.Paged[store.ActionVersion], error) {
	q := r.req(tid)
	q.ActionId, q.Page, q.PerPage = actionID, int64(p.Page), int64(p.PerPage)
	out := store.Paged[store.ActionVersion]{Items: []store.ActionVersion{}}
	v, err := r.call("ListVersions", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsListVersions(ctx, q) })
	if err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	for _, x := range v.Versions {
		if x == nil {
			return out, fmt.Errorf("%w: plugin returned a nil version", store.ErrInvalid)
		}
		out.Items = append(out.Items, *versionFromPB(x))
	}
	return out, nil
}
func (srv *Server) ActionsListVersions(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		p, err := a.ListVersions(ctx, q.TenantId, q.ActionId, store.PageRequest{Page: int(q.Page), PerPage: int(q.PerPage)})
		o.Total = int64(p.Total)
		for i := range p.Items {
			o.Versions = append(o.Versions, versionToPB(&p.Items[i]))
		}
		return err
	}), nil
}

func (r clientActions) PutBuild(ctx context.Context, b *store.Build) error {
	q := r.req(b.TenantID)
	q.Build = buildToPB(b)
	_, err := r.call("PutBuild", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsPutBuild(ctx, q) })
	return err
}
func (srv *Server) ActionsPutBuild(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.PutBuild(ctx, buildFromPB(q.Build))
	}), nil
}

func (r clientActions) GetBuild(ctx context.Context, tid, id string) (*store.Build, error) {
	q := r.req(tid)
	q.Id = id
	v, err := r.call("GetBuild", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetBuild(ctx, q) })
	if err != nil {
		return nil, err
	}
	return buildFromPB(v.Build), nil
}
func (srv *Server) ActionsGetBuild(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetBuild(ctx, q.TenantId, q.Id)
		o.Build = buildToPB(v)
		return err
	}), nil
}

// PutArtifact streams the tarball in chunks. The header message carries the
// size and SHA-256 the server verifies before storing.
func (r clientActions) PutArtifact(ctx context.Context, tid, buildID string, tar []byte) error {
	if int64(len(tar)) > maxArtifact() {
		return fmt.Errorf("%w: artifact exceeds %d bytes", store.ErrInvalid, maxArtifact())
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := r.c.rpc.ActionsPutArtifact(ctx)
	if err != nil {
		return actionsErr("PutArtifact", err)
	}
	sum := sha256.Sum256(tar)
	first := true
	for off := 0; first || off < len(tar); {
		end := min(off+artifactChunk, len(tar))
		m := &storev1.ActionsArtifactChunk{Data: tar[off:end]}
		if first {
			m.TxId, m.TenantId, m.BuildId, m.TotalSize, m.Sha256 = r.c.txID, tid, buildID, int64(len(tar)), sum[:]
			first = false
		}
		if err := stream.Send(m); err != nil {
			if errors.Is(err, io.EOF) { // the server answered early; Recv has the reason
				break
			}
			return actionsErr("PutArtifact", err)
		}
		off = end
	}
	res, err := stream.CloseAndRecv()
	if err != nil {
		return actionsErr("PutArtifact", err)
	}
	return errFromPB(res.GetError())
}

func (srv *Server) ActionsPutArtifact(stream grpc.ClientStreamingServer[storev1.ActionsArtifactChunk, storev1.Result]) error {
	h, err := stream.Recv()
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	// Reject an out-of-range declared size before buffering anything.
	if h.TotalSize < 0 || h.TotalSize > maxArtifact() {
		return stream.SendAndClose(&storev1.Result{Error: errToPB(fmt.Errorf("%w: artifact size %d", store.ErrInvalid, h.TotalSize))})
	}
	buf.Grow(int(h.TotalSize))
	m := h
	for {
		if int64(buf.Len()+len(m.Data)) > h.TotalSize {
			return stream.SendAndClose(&storev1.Result{Error: errToPB(fmt.Errorf("%w: artifact exceeds declared size", store.ErrInvalid))})
		}
		buf.Write(m.Data)
		if m, err = stream.Recv(); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
	}
	sum := sha256.Sum256(buf.Bytes())
	if int64(buf.Len()) != h.TotalSize || !bytes.Equal(sum[:], h.Sha256) {
		return stream.SendAndClose(&storev1.Result{Error: errToPB(fmt.Errorf("%w: artifact failed size or SHA-256 verification", store.ErrInvalid))})
	}
	err = srv.with(h.TxId, func(s store.Store) error {
		return s.Actions().PutArtifact(stream.Context(), h.TenantId, h.BuildId, buf.Bytes())
	})
	return stream.SendAndClose(&storev1.Result{Error: errToPB(err)})
}

func (r clientActions) GetArtifact(ctx context.Context, tid, buildID string) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	q := r.req(tid)
	q.BuildId = buildID
	stream, err := r.c.rpc.ActionsGetArtifact(ctx, q)
	if err != nil {
		return nil, actionsErr("GetArtifact", err)
	}
	var (
		buf     bytes.Buffer
		size    int64 = -1
		wantSum []byte
	)
	for {
		m, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, actionsErr("GetArtifact", err)
		}
		// A store failure arrives in-band: the server cannot change the
		// status of a stream it has already begun.
		if e := errFromPB(m.GetError()); e != nil {
			return nil, e
		}
		if size < 0 {
			if m.TotalSize < 0 || m.TotalSize > maxArtifact() || len(m.Sha256) != sha256.Size {
				return nil, errors.New("storage plugin Actions: GetArtifact: malformed artifact header")
			}
			size, wantSum = m.TotalSize, m.Sha256
			buf.Grow(int(size))
		}
		if int64(buf.Len()+len(m.Data)) > size {
			return nil, errors.New("storage plugin Actions: GetArtifact: artifact exceeds declared size")
		}
		buf.Write(m.Data)
	}
	sum := sha256.Sum256(buf.Bytes())
	if size < 0 || int64(buf.Len()) != size || !bytes.Equal(sum[:], wantSum) {
		return nil, errors.New("storage plugin Actions: GetArtifact: artifact failed size or SHA-256 verification")
	}
	return buf.Bytes(), nil
}

func (srv *Server) ActionsGetArtifact(q *storev1.ActionsRequest, stream grpc.ServerStreamingServer[storev1.ActionsArtifactChunk]) error {
	var data []byte
	err := srv.with(q.TxId, func(s store.Store) (e error) {
		data, e = s.Actions().GetArtifact(stream.Context(), q.TenantId, q.BuildId)
		return e
	})
	if err != nil {
		return stream.Send(&storev1.ActionsArtifactChunk{Error: errToPB(err)})
	}
	sum := sha256.Sum256(data)
	first := true
	for off := 0; first || off < len(data); {
		end := min(off+artifactChunk, len(data))
		m := &storev1.ActionsArtifactChunk{Data: data[off:end]}
		if first {
			m.TotalSize, m.Sha256 = int64(len(data)), sum[:]
			first = false
		}
		if err := stream.Send(m); err != nil {
			return err
		}
		off = end
	}
	return nil
}

func (r clientActions) Bindings(ctx context.Context, tid, trigger string) ([]store.BoundVersion, error) {
	q := r.req(tid)
	q.Trigger = trigger
	v, err := r.call("Bindings", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsBindings(ctx, q) })
	if err != nil {
		return nil, err
	}
	return boundFromPB(v.Bound), nil
}
func (srv *Server) ActionsBindings(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.Bindings(ctx, q.TenantId, q.Trigger)
		o.Bound = boundToPB(v)
		return err
	}), nil
}

func (r clientActions) ReplaceBindings(ctx context.Context, tid, trigger string, b []store.Binding) ([]store.BoundVersion, error) {
	q := r.req(tid)
	q.Trigger = trigger
	q.Bindings = []*storev1.ActionBindingMsg{}
	for _, x := range b {
		q.Bindings = append(q.Bindings, bindingToPB(x))
	}
	v, err := r.call("ReplaceBindings", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsReplaceBindings(ctx, q) })
	if err != nil {
		return nil, err
	}
	return boundFromPB(v.Bound), nil
}
func (srv *Server) ActionsReplaceBindings(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		bs := make([]store.Binding, 0, len(q.Bindings))
		for _, x := range q.Bindings {
			bs = append(bs, bindingFromPB(x))
		}
		v, err := a.ReplaceBindings(ctx, q.TenantId, q.Trigger, bs)
		o.Bound = boundToPB(v)
		return err
	}), nil
}

func (r clientActions) CreateExecution(ctx context.Context, e *store.Execution) error {
	q := r.req(e.TenantID)
	q.Execution = executionToPB(e)
	_, err := r.call("CreateExecution", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsCreateExecution(ctx, q) })
	return err
}
func (srv *Server) ActionsCreateExecution(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.CreateExecution(ctx, executionFromPB(q.Execution))
	}), nil
}

func (r clientActions) GetExecution(ctx context.Context, tid, id string) (*store.Execution, error) {
	q := r.req(tid)
	q.Id = id
	v, err := r.call("GetExecution", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetExecution(ctx, q) })
	if err != nil {
		return nil, err
	}
	return executionFromPB(v.Execution), nil
}
func (srv *Server) ActionsGetExecution(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetExecution(ctx, q.TenantId, q.Id)
		o.Execution = executionToPB(v)
		return err
	}), nil
}

func (r clientActions) PurgeExecutions(ctx context.Context, before time.Time) (int, error) {
	q := r.req("")
	q.Time = tsToPB(before)
	v, err := r.call("PurgeExecutions", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsPurgeExecutions(ctx, q) })
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (srv *Server) ActionsPurgeExecutions(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		n, err := a.PurgeExecutions(ctx, tsFromPB(q.Time))
		o.Count = int64(n)
		return err
	}), nil
}

func (r clientActions) CreateContinue(ctx context.Context, c *store.ContinueState) error {
	q := r.req(c.TenantID)
	q.ContinueState = continueToPB(c)
	_, err := r.call("CreateContinue", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsCreateContinue(ctx, q) })
	return err
}
func (srv *Server) ActionsCreateContinue(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, _ *storev1.ActionsResponse) error {
		return a.CreateContinue(ctx, continueFromPB(q.ContinueState))
	}), nil
}

func (r clientActions) ConsumeContinue(ctx context.Context, tid, stateHash string, now time.Time) (*store.ContinueState, error) {
	q := r.req(tid)
	q.StateHash, q.Time = stateHash, tsToPB(now)
	v, err := r.call("ConsumeContinue", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsConsumeContinue(ctx, q) })
	if err != nil {
		return nil, err
	}
	return continueFromPB(v.ContinueState), nil
}
func (srv *Server) ActionsConsumeContinue(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.ConsumeContinue(ctx, q.TenantId, q.StateHash, tsFromPB(q.Time))
		o.ContinueState = continueToPB(v)
		return err
	}), nil
}

func (r clientActions) PurgeContinue(ctx context.Context, before time.Time) (int, error) {
	q := r.req("")
	q.Time = tsToPB(before)
	v, err := r.call("PurgeContinue", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsPurgeContinue(ctx, q) })
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (srv *Server) ActionsPurgeContinue(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		n, err := a.PurgeContinue(ctx, tsFromPB(q.Time))
		o.Count = int64(n)
		return err
	}), nil
}
