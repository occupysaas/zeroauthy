package grpcstore

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
	storev1 "github.com/zeroauthy/zeroauthy/proto/store/v1"
	"google.golang.org/protobuf/types/known/durationpb"
)

func moduleRefsToPB(refs []store.ModuleRef) []*storev1.ActionModuleRefMsg {
	out := make([]*storev1.ActionModuleRefMsg, 0, len(refs))
	for _, r := range refs {
		out = append(out, &storev1.ActionModuleRefMsg{ModuleId: r.ModuleID, ModuleName: r.ModuleName, VersionId: r.VersionID, VersionNumber: int64(r.VersionNumber)})
	}
	return out
}
func moduleRefsFromPB(refs []*storev1.ActionModuleRefMsg) []store.ModuleRef {
	if refs == nil {
		return nil
	}
	out := make([]store.ModuleRef, 0, len(refs))
	for _, r := range refs {
		out = append(out, store.ModuleRef{ModuleID: r.GetModuleId(), ModuleName: r.GetModuleName(), VersionID: r.GetVersionId(), VersionNumber: int(r.GetVersionNumber())})
	}
	return out
}
func moduleToPB(m *store.ActionModule) *storev1.ActionModuleMsg {
	if m == nil {
		return nil
	}
	return &storev1.ActionModuleMsg{
		TenantId: m.TenantID, Id: m.ID, Name: m.Name, Code: m.Code,
		Dependencies: depsToPB(m.Dependencies), Secrets: secretsToPB(m.Secrets), DraftBuildId: m.DraftBuildID,
		LatestVersionNumber: int64(m.LatestVersionNumber), AllChangesPublished: m.AllChangesPublished,
		CreatedAt: tsToPB(m.CreatedAt), UpdatedAt: tsToPB(m.UpdatedAt),
	}
}
func moduleFromPB(m *storev1.ActionModuleMsg) *store.ActionModule {
	if m == nil {
		return nil
	}
	return &store.ActionModule{
		TenantID: m.TenantId, ID: m.Id, Name: m.Name, Code: m.Code,
		Dependencies: depsFromPB(m.Dependencies), Secrets: secretsFromPB(m.Secrets), DraftBuildID: m.DraftBuildId,
		LatestVersionNumber: int(m.LatestVersionNumber), AllChangesPublished: m.AllChangesPublished,
		CreatedAt: tsFromPB(m.CreatedAt), UpdatedAt: tsFromPB(m.UpdatedAt),
	}
}
func moduleVersionToPB(v *store.ActionModuleVersion) *storev1.ActionModuleVersionMsg {
	if v == nil {
		return nil
	}
	return &storev1.ActionModuleVersionMsg{
		TenantId: v.TenantID, ModuleId: v.ModuleID, Id: v.ID, Number: int64(v.Number), Code: v.Code, BuildId: v.BuildID,
		Dependencies: depsToPB(v.Dependencies), Secrets: secretsToPB(v.Secrets), CreatedAt: tsToPB(v.CreatedAt),
	}
}
func moduleVersionFromPB(v *storev1.ActionModuleVersionMsg) *store.ActionModuleVersion {
	if v == nil {
		return nil
	}
	return &store.ActionModuleVersion{
		TenantID: v.TenantId, ModuleID: v.ModuleId, ID: v.Id, Number: int(v.Number), Code: v.Code, BuildID: v.BuildId,
		Dependencies: depsFromPB(v.Dependencies), Secrets: secretsFromPB(v.Secrets), CreatedAt: tsFromPB(v.CreatedAt),
	}
}
func moduleUserToPB(u *store.ModuleUser) *storev1.ActionModuleUserMsg {
	return &storev1.ActionModuleUserMsg{Action: actionToPB(&u.Action), InDraft: u.InDraft, InDeployed: u.InDeployed}
}
func moduleUserFromPB(u *storev1.ActionModuleUserMsg) *store.ModuleUser {
	if u == nil || u.Action == nil {
		return nil
	}
	return &store.ModuleUser{Action: *actionFromPB(u.Action), InDraft: u.InDraft, InDeployed: u.InDeployed}
}
func actionJobToPB(j *store.ActionJob) *storev1.ActionJobMsg {
	if j == nil {
		return nil
	}
	return &storev1.ActionJobMsg{
		TenantId: j.TenantID, Id: j.ID, Trigger: j.Trigger, Status: j.Status, Sealed: j.Sealed, Attempts: int64(j.Attempts),
		NextAt: tsToPB(j.NextAt), LeaseUntil: tsToPB(j.LeaseUntil), CreatedAt: tsToPB(j.CreatedAt), UpdatedAt: tsToPB(j.UpdatedAt),
		ExecutionIds: j.ExecutionIDs, ModuleVersionIds: j.ModuleVersionIDs,
	}
}
func actionJobFromPB(j *storev1.ActionJobMsg) *store.ActionJob {
	if j == nil {
		return nil
	}
	return &store.ActionJob{
		TenantID: j.TenantId, ID: j.Id, Trigger: j.Trigger, Status: j.Status, Sealed: j.Sealed, Attempts: int(j.Attempts),
		NextAt: tsFromPB(j.NextAt), LeaseUntil: tsFromPB(j.LeaseUntil), CreatedAt: tsFromPB(j.CreatedAt), UpdatedAt: tsFromPB(j.UpdatedAt),
		ExecutionIDs: j.ExecutionIds, ModuleVersionIDs: j.ModuleVersionIds,
	}
}

func (r clientActions) CreateModule(ctx context.Context, m *store.ActionModule) error {
	q := r.req(m.TenantID)
	q.Module = moduleToPB(m)
	_, err := r.call("CreateModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsCreateModule(ctx, q) })
	return err
}
func (srv *Server) ActionsCreateModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		return a.CreateModule(ctx, moduleFromPB(q.Module))
	}), nil
}

func (r clientActions) UpdateModule(ctx context.Context, m *store.ActionModule) error {
	q := r.req(m.TenantID)
	q.Module = moduleToPB(m)
	_, err := r.call("UpdateModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsUpdateModule(ctx, q) })
	return err
}
func (srv *Server) ActionsUpdateModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		return a.UpdateModule(ctx, moduleFromPB(q.Module))
	}), nil
}

func (r clientActions) GetModule(ctx context.Context, tid, id string) (*store.ActionModule, error) {
	q := r.req(tid)
	q.Id = id
	v, err := r.call("GetModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetModule(ctx, q) })
	if err != nil {
		return nil, err
	}
	return moduleFromPB(v.Module), nil
}
func (srv *Server) ActionsGetModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetModule(ctx, q.TenantId, q.Id)
		o.Module = moduleToPB(v)
		return err
	}), nil
}

func (r clientActions) GetModuleByName(ctx context.Context, tid, name string) (*store.ActionModule, error) {
	q := r.req(tid)
	q.Name = name
	v, err := r.call("GetModuleByName", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetModuleByName(ctx, q) })
	if err != nil {
		return nil, err
	}
	return moduleFromPB(v.Module), nil
}
func (srv *Server) ActionsGetModuleByName(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetModuleByName(ctx, q.TenantId, q.Name)
		o.Module = moduleToPB(v)
		return err
	}), nil
}

func (r clientActions) DeleteModule(ctx context.Context, tid, id string) error {
	q := r.req(tid)
	q.Id = id
	_, err := r.call("DeleteModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsDeleteModule(ctx, q) })
	return err
}
func (srv *Server) ActionsDeleteModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		return a.DeleteModule(ctx, q.TenantId, q.Id)
	}), nil
}

func (r clientActions) PublishModule(ctx context.Context, tid, id string) (*store.ActionModuleVersion, error) {
	q := r.req(tid)
	q.Id = id
	v, err := r.call("PublishModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsPublishModule(ctx, q) })
	if err != nil {
		return nil, err
	}
	return moduleVersionFromPB(v.ModuleVersion), nil
}
func (srv *Server) ActionsPublishModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.PublishModule(ctx, q.TenantId, q.Id)
		o.ModuleVersion = moduleVersionToPB(v)
		return err
	}), nil
}

func (r clientActions) RollbackModule(ctx context.Context, tid, id, versionID string) (*store.ActionModule, error) {
	q := r.req(tid)
	q.Id, q.VersionId = id, versionID
	v, err := r.call("RollbackModule", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsRollbackModule(ctx, q) })
	if err != nil {
		return nil, err
	}
	return moduleFromPB(v.Module), nil
}
func (srv *Server) ActionsRollbackModule(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.RollbackModule(ctx, q.TenantId, q.Id, q.VersionId)
		o.Module = moduleToPB(v)
		return err
	}), nil
}

func (r clientActions) GetModuleVersion(ctx context.Context, tid, id, versionID string) (*store.ActionModuleVersion, error) {
	q := r.req(tid)
	q.Id, q.VersionId = id, versionID
	v, err := r.call("GetModuleVersion", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsGetModuleVersion(ctx, q) })
	if err != nil {
		return nil, err
	}
	return moduleVersionFromPB(v.ModuleVersion), nil
}
func (srv *Server) ActionsGetModuleVersion(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		v, err := a.GetModuleVersion(ctx, q.TenantId, q.Id, q.VersionId)
		o.ModuleVersion = moduleVersionToPB(v)
		return err
	}), nil
}

func (r clientActions) EnqueueJob(ctx context.Context, j *store.ActionJob) error {
	q := r.req(j.TenantID)
	q.Job = actionJobToPB(j)
	_, err := r.call("EnqueueJob", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsEnqueueJob(ctx, q) })
	return err
}
func (srv *Server) ActionsEnqueueJob(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		return a.EnqueueJob(ctx, actionJobFromPB(q.Job))
	}), nil
}

func (r clientActions) FinishJob(ctx context.Context, j *store.ActionJob, leaseUntil time.Time) error {
	q := r.req(j.TenantID)
	q.Job, q.LeaseUntil = actionJobToPB(j), tsToPB(leaseUntil)
	_, err := r.call("FinishJob", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsFinishJob(ctx, q) })
	return err
}
func (srv *Server) ActionsFinishJob(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		return a.FinishJob(ctx, actionJobFromPB(q.Job), tsFromPB(q.LeaseUntil))
	}), nil
}

func (r clientActions) ListModules(ctx context.Context, tid string, p store.PageRequest) (store.Paged[store.ActionModule], error) {
	q := r.req(tid)
	q.Page, q.PerPage = int64(p.Page), int64(p.PerPage)
	out := store.Paged[store.ActionModule]{Items: []store.ActionModule{}}
	v, err := r.call("ListModules", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsListModules(ctx, q) })
	if err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	for _, x := range v.Modules {
		value := moduleFromPB(x)
		if value == nil {
			return out, fmt.Errorf("%w: plugin returned a nil ActionModule", store.ErrInvalid)
		}
		out.Items = append(out.Items, *value)
	}
	return out, nil
}
func (srv *Server) ActionsListModules(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		p, err := a.ListModules(ctx, q.TenantId, store.PageRequest{Page: int(q.Page), PerPage: int(q.PerPage)})
		o.Total = int64(p.Total)
		for i := range p.Items {
			o.Modules = append(o.Modules, moduleToPB(&p.Items[i]))
		}
		return err
	}), nil
}

func (r clientActions) ListModuleVersions(ctx context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ActionModuleVersion], error) {
	q := r.req(tid)
	q.Id, q.Page, q.PerPage = id, int64(p.Page), int64(p.PerPage)
	out := store.Paged[store.ActionModuleVersion]{Items: []store.ActionModuleVersion{}}
	v, err := r.call("ListModuleVersions", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsListModuleVersions(ctx, q) })
	if err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	for _, x := range v.ModuleVersions {
		value := moduleVersionFromPB(x)
		if value == nil {
			return out, fmt.Errorf("%w: plugin returned a nil ActionModuleVersion", store.ErrInvalid)
		}
		out.Items = append(out.Items, *value)
	}
	return out, nil
}
func (srv *Server) ActionsListModuleVersions(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		p, err := a.ListModuleVersions(ctx, q.TenantId, q.Id, store.PageRequest{Page: int(q.Page), PerPage: int(q.PerPage)})
		o.Total = int64(p.Total)
		for i := range p.Items {
			o.ModuleVersions = append(o.ModuleVersions, moduleVersionToPB(&p.Items[i]))
		}
		return err
	}), nil
}

func (r clientActions) ModuleUsers(ctx context.Context, tid, id string, p store.PageRequest) (store.Paged[store.ModuleUser], error) {
	q := r.req(tid)
	q.Id, q.Page, q.PerPage = id, int64(p.Page), int64(p.PerPage)
	out := store.Paged[store.ModuleUser]{Items: []store.ModuleUser{}}
	v, err := r.call("ModuleUsers", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsModuleUsers(ctx, q) })
	if err != nil {
		return out, err
	}
	out.Total = int(v.Total)
	for _, x := range v.ModuleUsers {
		value := moduleUserFromPB(x)
		if value == nil {
			return out, fmt.Errorf("%w: plugin returned a nil ModuleUser", store.ErrInvalid)
		}
		out.Items = append(out.Items, *value)
	}
	return out, nil
}
func (srv *Server) ActionsModuleUsers(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		p, err := a.ModuleUsers(ctx, q.TenantId, q.Id, store.PageRequest{Page: int(q.Page), PerPage: int(q.PerPage)})
		o.Total = int64(p.Total)
		for i := range p.Items {
			o.ModuleUsers = append(o.ModuleUsers, moduleUserToPB(&p.Items[i]))
		}
		return err
	}), nil
}

func (r clientActions) ClaimJobs(ctx context.Context, now time.Time, lease time.Duration, maxJobs int) ([]store.ActionJob, error) {
	q := r.req("")
	q.Time, q.Lease, q.MaxJobs = tsToPB(now), durationpb.New(lease), int64(maxJobs)
	v, err := r.call("ClaimJobs", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsClaimJobs(ctx, q) })
	if err != nil {
		return nil, err
	}
	out := make([]store.ActionJob, 0, len(v.Jobs))
	for _, j := range v.Jobs {
		if j == nil {
			return nil, fmt.Errorf("%w: plugin returned a nil ActionJob", store.ErrInvalid)
		}
		out = append(out, *actionJobFromPB(j))
	}
	return out, nil
}
func (srv *Server) ActionsClaimJobs(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		if q.Lease == nil || q.Lease.CheckValid() != nil {
			return store.ErrInvalid
		}
		jobs, err := a.ClaimJobs(ctx, tsFromPB(q.Time), q.Lease.AsDuration(), int(q.MaxJobs))
		for i := range jobs {
			o.Jobs = append(o.Jobs, actionJobToPB(&jobs[i]))
		}
		return err
	}), nil
}
func (r clientActions) PurgeJobs(ctx context.Context, before time.Time) (int, error) {
	q := r.req("")
	q.Time = tsToPB(before)
	v, err := r.call("PurgeJobs", func() (*storev1.ActionsResponse, error) { return r.c.rpc.ActionsPurgeJobs(ctx, q) })
	if err != nil {
		return 0, err
	}
	return int(v.Count), nil
}
func (srv *Server) ActionsPurgeJobs(ctx context.Context, q *storev1.ActionsRequest) (*storev1.ActionsResponse, error) {
	return srv.actionsServe(q, func(a store.Actions, o *storev1.ActionsResponse) error {
		n, err := a.PurgeJobs(ctx, tsFromPB(q.Time))
		o.Count = int64(n)
		return err
	}), nil
}
func (r clientPasswordResetTickets) MarkChallengePassed(ctx context.Context, tid, tokenHash string, at time.Time, resultURL string) error {
	res, err := r.c.rpc.PasswordResetTicketsMarkChallengePassed(ctx, &storev1.PasswordResetTicketChallengeRequest{TxId: r.c.txID, TenantId: tid, TokenHash: tokenHash, PassedAt: tsToPB(at), ResultUrl: resultURL})
	if err != nil {
		return actionsErr("MarkChallengePassed", err)
	}
	return errFromPB(res.GetError())
}
func (srv *Server) PasswordResetTicketsMarkChallengePassed(ctx context.Context, q *storev1.PasswordResetTicketChallengeRequest) (*storev1.Result, error) {
	if err := checkTS(q.PassedAt); err != nil {
		return &storev1.Result{Error: errToPB(store.ErrInvalid)}, nil
	}
	err := srv.with(q.TxId, func(s store.Store) error {
		return s.PasswordResetTickets().MarkChallengePassed(ctx, q.TenantId, q.TokenHash, tsFromPB(q.PassedAt), q.ResultUrl)
	})
	return &storev1.Result{Error: errToPB(err)}, nil
}
