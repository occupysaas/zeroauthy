package store

import "time"

// ModuleRef identifies a module version. Stored refs contain both ID and name pairs.
type ModuleRef struct {
	ModuleID, ModuleName, VersionID string
	VersionNumber                   int
}
type ActionModule struct {
	TenantID, ID, Name, Code string
	Dependencies             []Dependency
	Secrets                  []ActionSecret
	DraftBuildID             string
	LatestVersionNumber      int
	AllChangesPublished      bool
	CreatedAt, UpdatedAt     time.Time
}
type ActionModuleVersion struct {
	TenantID, ModuleID, ID string
	Number                 int
	Code, BuildID          string
	Dependencies           []Dependency
	Secrets                []ActionSecret
	CreatedAt              time.Time
}

// ModuleUser is one Action using the module in its draft or deployed version.
type ModuleUser struct {
	Action
	InDraft, InDeployed bool
}
