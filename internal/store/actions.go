package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrActionsUnavailable is returned by stores without an Actions repository.
	ErrActionsUnavailable = errors.New("store: Actions capability unavailable")
	// ErrBuildNotReady is returned by Deploy when the draft has no built artifact.
	ErrBuildNotReady = errors.New("store: action draft build is not ready")
)

// ActionsSupporter is implemented by remote stores that negotiate Actions
// support; a store that cannot serve Actions must fail startup, never read as
// an empty registry.
type ActionsSupporter interface{ CheckActionsSupport(context.Context) error }

// BuildStatus is the lifecycle state of a dependency build.
type BuildStatus string

const (
	BuildPending  BuildStatus = "pending"
	BuildBuilding BuildStatus = "building"
	BuildBuilt    BuildStatus = "built"
	BuildFailed   BuildStatus = "failed"
)

// Valid reports whether s is a known build status.
func (s BuildStatus) Valid() bool {
	switch s {
	case BuildPending, BuildBuilding, BuildBuilt, BuildFailed:
		return true
	}
	return false
}

// Dependency is one npm package. Version is exact semver, or empty for latest.
type Dependency struct{ Name, Version string }

// ActionSecret is a named secret whose value is sealed at rest.
type ActionSecret struct {
	Name      string
	Sealed    []byte
	UpdatedAt time.Time
}

// Action is a tenant's Action and its mutable draft.
type Action struct {
	TenantID, ID, Name, Trigger, Runtime, Code string
	Modules                                    []ModuleRef
	Dependencies                               []Dependency
	Secrets                                    []ActionSecret
	DraftBuildID                               string
	DeployedVersionID                          string
	CreatedAt, UpdatedAt                       time.Time
}

// ActionVersion is an immutable deployed snapshot of an Action.
type ActionVersion struct {
	TenantID, ActionID, ID string
	Number                 int
	Code, Runtime, BuildID string
	Modules                []ModuleRef
	Dependencies           []Dependency // resolved
	Secrets                []ActionSecret
	CreatedAt              time.Time
}

// Build records one content-addressed dependency build. ID is the sha256 of
// the runtime and the sorted resolved dependencies.
type Build struct {
	TenantID, ID   string
	Status         BuildStatus
	Requested      []Dependency
	Resolved       []Dependency
	Errors         []string
	ArtifactSHA256 string
	BuiltAt        time.Time
}

// Binding attaches an Action to a trigger at a position.
type Binding struct {
	TenantID, Trigger, ID, ActionID, DisplayName string
	CreatedAt, UpdatedAt                         time.Time
}

// BoundVersion is a binding with its Action and the version it runs.
type BoundVersion struct {
	Binding
	Action  Action
	Version ActionVersion
}

// Execution is the record of one trigger execution.
type Execution struct {
	TenantID, ID, Trigger, Status string
	Results                       []ExecutionResult
	CreatedAt, UpdatedAt          time.Time
}

// ExecutionResult is one Action's outcome within an execution.
type ExecutionResult struct {
	// JobID and JobAttempt identify this immutable asynchronous attempt.
	JobID                         string
	JobAttempt                    int
	ActionName, ErrorID, ErrorMsg string
	StartedAt, EndedAt            time.Time
}

// ContinueState is the single-use state behind a post-login redirect.
type ContinueState struct {
	TenantID, StateHash, SessionID string
	Sealed                         []byte
	ExpiresAt, CreatedAt           time.Time
}

// PageRequest selects a zero-based page. PerPage 0 means DefaultPerPage and
// values above MaxPerPage are clamped.
type PageRequest struct{ Page, PerPage int }

const (
	DefaultPerPage = 20
	MaxPerPage     = 100
)

// Normalize applies the default and maximum page size.
func (p PageRequest) Normalize() PageRequest {
	if p.PerPage <= 0 {
		p.PerPage = DefaultPerPage
	}
	if p.PerPage > MaxPerPage {
		p.PerPage = MaxPerPage
	}
	if p.Page < 0 {
		p.Page = 0
	}
	return p
}

// Paged is one page of results and the total match count.
type Paged[T any] struct {
	Items []T
	Total int
}

// ActionFilter narrows ListActions. An empty Trigger matches every trigger.
type ActionFilter struct {
	Trigger string
	PageRequest
}

// Actions persists Actions, versions, builds, bindings, executions and
// continue states. Every method is tenant scoped.
type Actions interface {
	CreateModule(ctx context.Context, m *ActionModule) error
	GetModule(ctx context.Context, tenantID, id string) (*ActionModule, error)
	GetModuleByName(ctx context.Context, tenantID, name string) (*ActionModule, error)
	// UpdateModule replaces draft fields; names and publication metadata are immutable.
	UpdateModule(ctx context.Context, m *ActionModule) error
	// DeleteModule returns ErrPrecondition for draft/current deployment use;
	// older versions and jobs retain hidden runtime tombstones.
	DeleteModule(ctx context.Context, tenantID, id string) error
	ListModules(ctx context.Context, tenantID string, p PageRequest) (Paged[ActionModule], error)
	// PublishModule atomically snapshots the draft. Unchanged drafts return ErrConflict,
	// exhausted version limits ErrPrecondition, and unavailable artifacts ErrBuildNotReady.
	PublishModule(ctx context.Context, tenantID, id string) (*ActionModuleVersion, error)
	RollbackModule(ctx context.Context, tenantID, id, versionID string) (*ActionModule, error)
	ListModuleVersions(ctx context.Context, tenantID, id string, p PageRequest) (Paged[ActionModuleVersion], error)
	// GetModuleVersion also reads hidden tombstones retained by immutable pins.
	GetModuleVersion(ctx context.Context, tenantID, moduleID, versionID string) (*ActionModuleVersion, error)
	ModuleUsers(ctx context.Context, tenantID, moduleID string, p PageRequest) (Paged[ModuleUser], error)
	// EnqueueJob returns ErrPrecondition at the per-tenant pending cap.
	EnqueueJob(ctx context.Context, j *ActionJob) error
	// ClaimJobs atomically leases due pending jobs in NextAt order across tenants.
	ClaimJobs(ctx context.Context, now time.Time, lease time.Duration, max int) ([]ActionJob, error)
	// FinishJob updates worker state only if the lease still matches (ErrConflict otherwise).
	FinishJob(ctx context.Context, j *ActionJob, leaseUntil time.Time) error
	// PurgeJobs removes terminal jobs, their execution records and unpinned tombstones.
	PurgeJobs(ctx context.Context, before time.Time) (int, error)

	CreateAction(ctx context.Context, a *Action) error
	GetAction(ctx context.Context, tenantID, id string) (*Action, error)
	GetActionByName(ctx context.Context, tenantID, name string) (*Action, error)
	// UpdateAction replaces the draft fields; trigger, creation time and the
	// deployed version are kept.
	UpdateAction(ctx context.Context, a *Action) error
	// DeleteAction returns ErrConflict when the Action is bound and force is
	// false; force also removes its bindings.
	DeleteAction(ctx context.Context, tenantID, id string, force bool) error
	ListActions(ctx context.Context, tenantID string, f ActionFilter) (Paged[Action], error)
	// Deploy allocates the next version number atomically. An empty
	// fromVersionID deploys the draft and needs a built DraftBuildID whose
	// artifact is stored (ErrBuildNotReady otherwise); otherwise it re-deploys that version as n+1.
	Deploy(ctx context.Context, tenantID, actionID, fromVersionID string) (*ActionVersion, error)
	GetVersion(ctx context.Context, tenantID, actionID, versionID string) (*ActionVersion, error)
	ListVersions(ctx context.Context, tenantID, actionID string, p PageRequest) (Paged[ActionVersion], error)
	PutBuild(ctx context.Context, b *Build) error
	GetBuild(ctx context.Context, tenantID, id string) (*Build, error)
	PutArtifact(ctx context.Context, tenantID, buildID string, tar []byte) error
	GetArtifact(ctx context.Context, tenantID, buildID string) ([]byte, error)
	// Bindings reads one consistent ordered snapshot.
	Bindings(ctx context.Context, tenantID, trigger string) ([]BoundVersion, error)
	// BindingsInitialized reports durable trigger initialization, including an
	// explicitly empty management or seed list. Missing tenants are ErrNotFound.
	BindingsInitialized(ctx context.Context, tenantID, trigger string) (bool, error)
	// InitializeBindings applies a seed only if the trigger is uninitialized.
	// The check, replacement and marker are atomic with ReplaceBindings. Once
	// initialized it returns the current list without resolving obsolete refs.
	InitializeBindings(ctx context.Context, tenantID, trigger string, b []Binding) ([]BoundVersion, error)
	// ReplaceBindings atomically replaces a trigger's bindings. Every Action
	// must exist, match the trigger and be deployed (ErrInvalid otherwise).
	// Every successful replacement durably marks the trigger initialized, even empty.
	ReplaceBindings(ctx context.Context, tenantID, trigger string, b []Binding) ([]BoundVersion, error)
	CreateExecution(ctx context.Context, e *Execution) error
	GetExecution(ctx context.Context, tenantID, id string) (*Execution, error)
	// PurgeExecutions deletes executions with CreatedAt before the cutoff.
	PurgeExecutions(ctx context.Context, before time.Time) (int, error)
	CreateContinue(ctx context.Context, c *ContinueState) error
	// ConsumeContinue is single use; an expired or absent state is ErrNotFound.
	// A state bound to another session is ErrNotFound and stays unconsumed,
	// so presenting it from a different session cannot burn it.
	ConsumeContinue(ctx context.Context, tenantID, stateHash, sessionID string, now time.Time) (*ContinueState, error)
	// PurgeContinue deletes states with ExpiresAt before the cutoff.
	PurgeContinue(ctx context.Context, before time.Time) (int, error)
}

// UnimplementedActions fails closed for stores awaiting an Actions implementation.
type UnimplementedActions struct{}

func (UnimplementedActions) CreateAction(context.Context, *Action) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) GetAction(context.Context, string, string) (*Action, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) GetActionByName(context.Context, string, string) (*Action, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) UpdateAction(context.Context, *Action) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) DeleteAction(context.Context, string, string, bool) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) ListActions(context.Context, string, ActionFilter) (Paged[Action], error) {
	return Paged[Action]{}, ErrActionsUnavailable
}
func (UnimplementedActions) Deploy(context.Context, string, string, string) (*ActionVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) GetVersion(context.Context, string, string, string) (*ActionVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) ListVersions(context.Context, string, string, PageRequest) (Paged[ActionVersion], error) {
	return Paged[ActionVersion]{}, ErrActionsUnavailable
}
func (UnimplementedActions) PutBuild(context.Context, *Build) error { return ErrActionsUnavailable }
func (UnimplementedActions) GetBuild(context.Context, string, string) (*Build, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) PutArtifact(context.Context, string, string, []byte) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) GetArtifact(context.Context, string, string) ([]byte, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) Bindings(context.Context, string, string) ([]BoundVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) ReplaceBindings(context.Context, string, string, []Binding) ([]BoundVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) CreateExecution(context.Context, *Execution) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) GetExecution(context.Context, string, string) (*Execution, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) PurgeExecutions(context.Context, time.Time) (int, error) {
	return 0, ErrActionsUnavailable
}
func (UnimplementedActions) CreateContinue(context.Context, *ContinueState) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) ConsumeContinue(context.Context, string, string, string, time.Time) (*ContinueState, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) PurgeContinue(context.Context, time.Time) (int, error) {
	return 0, ErrActionsUnavailable
}

func (UnimplementedActions) BindingsInitialized(context.Context, string, string) (bool, error) {
	return false, ErrActionsUnavailable
}
func (UnimplementedActions) InitializeBindings(context.Context, string, string, []Binding) ([]BoundVersion, error) {
	return nil, ErrActionsUnavailable
}

func (UnimplementedActions) CreateModule(context.Context, *ActionModule) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) GetModule(context.Context, string, string) (*ActionModule, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) GetModuleByName(context.Context, string, string) (*ActionModule, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) UpdateModule(context.Context, *ActionModule) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) DeleteModule(context.Context, string, string) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) ListModules(context.Context, string, PageRequest) (Paged[ActionModule], error) {
	return Paged[ActionModule]{}, ErrActionsUnavailable
}
func (UnimplementedActions) PublishModule(context.Context, string, string) (*ActionModuleVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) RollbackModule(context.Context, string, string, string) (*ActionModule, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) ListModuleVersions(context.Context, string, string, PageRequest) (Paged[ActionModuleVersion], error) {
	return Paged[ActionModuleVersion]{}, ErrActionsUnavailable
}
func (UnimplementedActions) GetModuleVersion(context.Context, string, string, string) (*ActionModuleVersion, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) ModuleUsers(context.Context, string, string, PageRequest) (Paged[ModuleUser], error) {
	return Paged[ModuleUser]{}, ErrActionsUnavailable
}
func (UnimplementedActions) EnqueueJob(context.Context, *ActionJob) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) ClaimJobs(context.Context, time.Time, time.Duration, int) ([]ActionJob, error) {
	return nil, ErrActionsUnavailable
}
func (UnimplementedActions) FinishJob(context.Context, *ActionJob, time.Time) error {
	return ErrActionsUnavailable
}
func (UnimplementedActions) PurgeJobs(context.Context, time.Time) (int, error) {
	return 0, ErrActionsUnavailable
}
