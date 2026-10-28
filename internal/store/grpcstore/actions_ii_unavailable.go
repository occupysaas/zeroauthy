package grpcstore

import (
	"context"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

func (clientActions) CreateModule(context.Context, *store.ActionModule) error {
	return store.ErrActionsUnavailable
}
func (clientActions) GetModule(context.Context, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) GetModuleByName(context.Context, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) UpdateModule(context.Context, *store.ActionModule) error {
	return store.ErrActionsUnavailable
}
func (clientActions) DeleteModule(context.Context, string, string) error {
	return store.ErrActionsUnavailable
}
func (clientActions) ListModules(context.Context, string, store.PageRequest) (store.Paged[store.ActionModule], error) {
	return store.Paged[store.ActionModule]{}, store.ErrActionsUnavailable
}
func (clientActions) PublishModule(context.Context, string, string) (*store.ActionModuleVersion, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) RollbackModule(context.Context, string, string, string) (*store.ActionModule, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) ListModuleVersions(context.Context, string, string, store.PageRequest) (store.Paged[store.ActionModuleVersion], error) {
	return store.Paged[store.ActionModuleVersion]{}, store.ErrActionsUnavailable
}
func (clientActions) GetModuleVersion(context.Context, string, string, string) (*store.ActionModuleVersion, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) ModuleUsers(context.Context, string, string, store.PageRequest) (store.Paged[store.ModuleUser], error) {
	return store.Paged[store.ModuleUser]{}, store.ErrActionsUnavailable
}
func (clientActions) EnqueueJob(context.Context, *store.ActionJob) error {
	return store.ErrActionsUnavailable
}
func (clientActions) ClaimJobs(context.Context, time.Time, time.Duration, int) ([]store.ActionJob, error) {
	return nil, store.ErrActionsUnavailable
}
func (clientActions) FinishJob(context.Context, *store.ActionJob, time.Time) error {
	return store.ErrActionsUnavailable
}
func (clientActions) PurgeJobs(context.Context, time.Time) (int, error) {
	return 0, store.ErrActionsUnavailable
}
func (clientPasswordResetTickets) MarkChallengePassed(context.Context, string, string, time.Time, string) error {
	return store.ErrActionsUnavailable
}
