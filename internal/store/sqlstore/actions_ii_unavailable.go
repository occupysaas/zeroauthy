package sqlstore

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (actionsRepo) CreateModule(context.Context, *store.ActionModule) error {
	return store.ErrActionsUnavailable
}
func (actionsRepo) GetModule(context.Context, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) GetModuleByName(context.Context, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) UpdateModule(context.Context, *store.ActionModule) error {
	return store.ErrActionsUnavailable
}
func (actionsRepo) DeleteModule(context.Context, string, string) error {
	return store.ErrActionsUnavailable
}
func (actionsRepo) ListModules(context.Context, string, store.PageRequest) (store.Paged[store.ActionModule], error) {
	return store.Paged[store.ActionModule]{}, store.ErrActionsUnavailable
}
func (actionsRepo) PublishModule(context.Context, string, string) (*store.ActionModuleVersion, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) RollbackModule(context.Context, string, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) ListModuleVersions(context.Context, string, string, store.PageRequest) (store.Paged[store.ActionModuleVersion], error) {
	return store.Paged[store.ActionModuleVersion]{}, store.ErrActionsUnavailable
}
func (actionsRepo) GetModuleVersion(context.Context, string, string, string) (*store.ActionModuleVersion, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) ModuleUsers(context.Context, string, string, store.PageRequest) (store.Paged[store.ModuleUser], error) {
	return store.Paged[store.ModuleUser]{}, store.ErrActionsUnavailable
}
func (actionsRepo) EnqueueJob(context.Context, *store.ActionJob) error {
	return store.ErrActionsUnavailable
}
func (actionsRepo) ClaimJobs(context.Context, time.Time, time.Duration, int) ([]store.ActionJob, error) {
	return nil, store.ErrActionsUnavailable
}
func (actionsRepo) FinishJob(context.Context, *store.ActionJob, time.Time) error {
	return store.ErrActionsUnavailable
}
func (actionsRepo) PurgeJobs(context.Context, time.Time) (int, error) {
	return 0, store.ErrActionsUnavailable
}
func (resetTickets) MarkChallengePassed(context.Context, string, string, time.Time, string) error {
	return store.ErrActionsUnavailable
}
