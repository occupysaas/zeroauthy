package dirsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/identity"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/scim"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Synchronization timing (Q11: Auth0 documents automatic runs about every
// 40 minutes).
const (
	AutomaticInterval = 40 * time.Minute
	lease             = 15 * time.Minute
	claimBatch        = 4
	pollInterval      = 30 * time.Second
	// maxUsers bounds one run.
	maxUsers = 200_000
)

// Synchronization outcomes stored as last_synchronization_status.
const (
	StatusSuccess = "success"
	StatusFailed  = "failed"
)

// suspendedMarker in an identity's profile data records that
// synchronization blocked the user, so only those blocks are lifted when the
// account is active again (LR37c-16); a block set by an administrator stays.
const suspendedMarker = "directory_suspended"

// Doc is a configuration's Management document.
type Doc struct {
	Mapping                  []store.SCIMMapping `json:"mapping"`
	SynchronizeAutomatically bool                `json:"synchronize_automatically"`
	SynchronizeGroups        string              `json:"synchronize_groups,omitempty"`
}

// DefaultMapping maps Directory API user fields (LR37c-16; Auth0 shows its
// default only in the Dashboard).
func DefaultMapping() []store.SCIMMapping {
	return []store.SCIMMapping{
		{Auth0: "email", SCIM: "primaryEmail"},
		{Auth0: "name", SCIM: "name.fullName"},
		{Auth0: "given_name", SCIM: "name.givenName"},
		{Auth0: "family_name", SCIM: "name.familyName"},
		{Auth0: "picture", SCIM: "thumbnailPhotoUrl"},
	}
}

// NewSyncID names a requested synchronization.
func NewSyncID() string { return "dsync_" + random()[:22] }

// schedule requests a synchronization now unless one is already pending.
func schedule(p *store.DirectoryProvisioning, now time.Time) string {
	if p.SyncID == "" || p.NextSyncAt == nil {
		p.SyncID = NewSyncID()
	}
	if p.NextSyncAt == nil || p.NextSyncAt.After(now) {
		t := now
		p.NextSyncAt = &t
	}
	return p.SyncID
}

// Schedule requests an on-demand synchronization and returns its ID.
func Schedule(p *store.DirectoryProvisioning, now time.Time) string { return schedule(p, now) }

// Syncer runs due synchronizations.
type Syncer struct {
	Store     store.Store
	Wrapper   keys.Wrapper
	Providers *federation.Providers
	Now       func() time.Time
	Log       *slog.Logger
	// EndSessions ends a blocked user's sessions with back-channel logout
	// (the server wires the logout service); nil deletes the sessions.
	EndSessions func(ctx context.Context, tx store.Store, tenantID, userID string) error
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Run claims and runs due synchronizations until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	if !store.DirectorySyncAvailable(s.Store) {
		return
	}
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		if _, err := s.RunDue(ctx); err != nil && ctx.Err() == nil {
			s.log().WarnContext(ctx, "directory synchronization claim failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue runs the synchronizations due now and returns how many ran.
func (s *Syncer) RunDue(ctx context.Context) (int, error) {
	due, err := s.Store.DirectorySync().ClaimDue(ctx, s.now(), lease, claimBatch)
	if err != nil {
		return 0, err
	}
	for _, p := range due {
		s.runOne(ctx, p)
	}
	return len(due), nil
}

func (s *Syncer) runOne(ctx context.Context, claimed *store.DirectoryProvisioning) {
	failures, err := s.sync(ctx, claimed)
	status, msg := StatusSuccess, ""
	switch {
	case err != nil:
		status, msg = StatusFailed, publicError(err)
	case failures > 0:
		status, msg = StatusFailed, fmt.Sprintf("%d users or groups could not be synchronized", failures)
	}
	now := s.now()
	ferr := s.Store.WithTx(ctx, func(tx store.Store) error {
		p, err := tx.DirectorySync().GetProvisioning(ctx, claimed.TenantID, claimed.ConnectionID)
		if err != nil {
			return err
		}
		p.LastSyncAt, p.LastSyncStatus, p.LastSyncError, p.LeaseUntil = &now, status, msg, nil
		if p.SyncID == claimed.SyncID {
			// No new request arrived during the run.
			p.SyncID, p.NextSyncAt = "", nil
			var d Doc
			if json.Unmarshal(p.Doc, &d) == nil && d.SynchronizeAutomatically {
				next := now.Add(AutomaticInterval)
				p.SyncID, p.NextSyncAt = NewSyncID(), &next
			}
		}
		return tx.DirectorySync().UpdateProvisioning(ctx, p)
	})
	if ferr != nil && !errors.Is(ferr, store.ErrNotFound) {
		s.log().WarnContext(ctx, "directory synchronization result not stored", "tenant", claimed.TenantID, "connection", claimed.ConnectionID, "error", ferr)
	}
	s.log().InfoContext(ctx, "directory synchronization finished", "tenant", claimed.TenantID, "connection", claimed.ConnectionID, "status", status, "failures", failures)
}

// errSetup is a configuration problem safe to show to the tenant.
type errSetup string

func (e errSetup) Error() string { return string(e) }

// publicError is the stored text of a failed run: fixed descriptions and
// HTTP statuses only.
func publicError(err error) string {
	var setup errSetup
	switch {
	case errors.As(err, &setup):
		return string(setup)
	case errors.Is(err, ErrGrantRevoked):
		return ErrGrantRevoked.Error()
	case errors.Is(err, ErrDirectory):
		return err.Error()
	}
	return "internal error"
}

type run struct {
	*Syncer
	ctx     context.Context
	conn    *store.Connection
	cfg     federation.Config
	mapping scim.Mapping
	client  *Client
	token   string
	// seen maps directory subjects to local user IDs.
	seen     map[string]string
	failures int
}

func (s *Syncer) sync(ctx context.Context, p *store.DirectoryProvisioning) (int, error) {
	conn, err := s.Store.Connections().Get(ctx, p.TenantID, p.ConnectionID)
	if err != nil {
		return 0, err
	}
	cfg, err := federation.ParseConfig(*connrules.FromConnection(conn))
	if err != nil || cfg.GoogleApps == nil || len(conn.FederationSecretsSealed) == 0 {
		return 0, errSetup("the connection is not a usable google-apps connection")
	}
	if !cfg.GoogleApps.APIEnableUsers {
		return 0, errSetup("options.api_enable_users is false")
	}
	if len(p.AdminGrant) == 0 {
		return 0, errSetup("a Google Workspace administrator has not authorized directory access")
	}
	var doc Doc
	if err := json.Unmarshal(p.Doc, &doc); err != nil {
		return 0, errSetup("the configuration is unreadable")
	}
	mapping, err := scim.ParseMapping(doc.Mapping)
	if err != nil {
		return 0, errSetup("the attribute mapping is invalid")
	}
	creds, err := federation.OpenCredentials(s.Wrapper, conn.TenantID, conn.ID, conn.FederationSecretsSealed)
	if err != nil {
		return 0, errSetup("the connection's credentials are unreadable")
	}
	refresh, err := OpenGrant(s.Wrapper, conn.TenantID, conn.ID, p.AdminGrant)
	if err != nil {
		return 0, errSetup("the administrator grant is unreadable; consent again")
	}
	endpoints, _, dirURL := s.Providers.Google()
	client := &Client{HTTP: s.Providers.HTTPClient(), TokenURL: endpoints.TokenURL, DirectoryURL: dirURL}
	token, err := client.AccessToken(ctx, cfg.ClientID, creds.ClientSecret, refresh)
	if err != nil {
		return 0, err
	}
	r := &run{Syncer: s, ctx: ctx, conn: conn, cfg: cfg, mapping: mapping, client: client, token: token, seen: map[string]string{}}
	count := 0
	err = client.Users(ctx, token, cfg.GoogleApps.Domain, func(u User) error {
		if count++; count > maxUsers {
			return errSetup(fmt.Sprintf("the directory has more than %d users", maxUsers))
		}
		if err := r.user(u); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r.failures++
			s.log().WarnContext(ctx, "directory user not synchronized", "tenant", conn.TenantID, "connection", conn.ID, "error", err)
		}
		return nil
	})
	if err != nil {
		return r.failures, err
	}
	// Users no longer in the directory are blocked only after a complete
	// listing.
	if err := r.blockMissing(); err != nil {
		return r.failures, err
	}
	if doc.SynchronizeGroups == "all" || doc.SynchronizeGroups == "selected" {
		if !cfg.GoogleApps.APIEnableGroups {
			return r.failures, errSetup("options.api_enable_groups is false")
		}
		if err := r.groups(p, doc.SynchronizeGroups == "all"); err != nil {
			return r.failures, err
		}
	}
	return r.failures, nil
}

func (r *run) subject(u User) string {
	if r.cfg.GoogleApps.MapUserIDToID {
		return u.ID
	}
	return strings.ToLower(u.PrimaryEmail)
}

// user creates or updates one directory user.
func (r *run) user(u User) error {
	sub := r.subject(u)
	if sub == "" || federation.ValidateSubject(sub) != nil {
		return errors.New("directory user without a usable identifier")
	}
	inactive := u.Suspended || u.Archived
	now := r.now()
	tid := r.conn.TenantID
	return r.Store.WithTx(r.ctx, func(tx store.Store) error {
		cur, err := tx.Users().FindByIdentity(r.ctx, tid, r.conn.ID, sub)
		if errors.Is(err, store.ErrNotFound) {
			nu := &store.User{TenantID: tid, UserID: store.FederatedPublicID(r.conn.Strategy, r.conn.Name, sub), CreatedAt: now, UpdatedAt: now,
				Identities: []store.Identity{{Connection: r.conn.Name, Provider: r.conn.Strategy, UserID: sub}}}
			if err := r.mapping.Apply(u.Raw, nu); err != nil {
				return err
			}
			nu.EmailVerified = nu.Email != ""
			nu.Name, nu.Nickname = identity.DefaultNames(nu.Name, nu.Nickname, nu.Email, "")
			if inactive {
				nu.Blocked = true
				nu.Identities[0].ProviderData = map[string]any{suspendedMarker: true}
			}
			if err := tx.Users().Create(r.ctx, nu); err != nil {
				return err
			}
			r.seen[sub] = nu.UserID
			return nil
		}
		if err != nil {
			return err
		}
		r.seen[sub] = cur.UserID
		before := copyUser(cur)
		if err := r.mapping.Apply(u.Raw, cur); err != nil {
			return err
		}
		if cur.Email != before.Email {
			cur.EmailVerified = cur.Email != ""
		}
		block := r.setActive(cur, !inactive)
		if equalUser(before, cur) {
			return nil
		}
		cur.UpdatedAt = now
		if err := tx.Users().Update(r.ctx, cur); err != nil {
			return err
		}
		if block {
			return r.deactivate(tx, cur.UserID)
		}
		return nil
	})
}

// identityIndex is the user's identity of the connection.
func (r *run) identityIndex(u *store.User) int {
	for i, id := range u.Identities {
		if id.Connection == r.conn.Name && id.Provider == r.conn.Strategy {
			return i
		}
	}
	return -1
}

// setActive applies the directory's account state and reports whether the
// user became blocked.
func (r *run) setActive(u *store.User, active bool) bool {
	i := r.identityIndex(u)
	if i < 0 {
		return false
	}
	marked, _ := u.Identities[i].ProviderData[suspendedMarker].(bool)
	switch {
	case !active && !u.Blocked:
		u.Blocked = true
		pd := maps.Clone(u.Identities[i].ProviderData)
		if pd == nil {
			pd = map[string]any{}
		}
		pd[suspendedMarker] = true
		u.Identities[i].ProviderData = pd
		return true
	case active && u.Blocked && marked:
		u.Blocked = false
		pd := maps.Clone(u.Identities[i].ProviderData)
		delete(pd, suspendedMarker)
		u.Identities[i].ProviderData = pd
	}
	return false
}

// copyUser is a deep copy through JSON (users are small).
func copyUser(u *store.User) *store.User {
	var out store.User
	b, _ := json.Marshal(u)
	_ = json.Unmarshal(b, &out)
	return &out
}

func equalUser(a, b *store.User) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// deactivate ends a newly blocked user's access as SCIM deprovisioning does.
func (r *run) deactivate(tx store.Store, uid string) error {
	tid := r.conn.TenantID
	if _, err := tx.Users().BumpVersion(r.ctx, tid, uid); err != nil {
		return err
	}
	if _, err := tx.RefreshTokens().RevokeByUser(r.ctx, tid, uid, r.now()); err != nil {
		return err
	}
	if r.EndSessions != nil {
		return r.EndSessions(r.ctx, tx, tid, uid)
	}
	_, err := tx.Sessions().DeleteByUser(r.ctx, tid, uid)
	return err
}

// blockMissing blocks the connection's users the directory no longer lists.
func (r *run) blockMissing() error {
	tid := r.conn.TenantID
	q := &store.UserQuery{Op: store.QueryTerm, Field: "identities.connection", Kind: store.KindString, Value: r.conn.Name}
	var missing []string
	for offset := 0; ; offset += 100 {
		users, _, err := r.Store.Users().List(r.ctx, tid, q, store.UserSort{Field: "user_id"}, store.Page{Offset: offset, Limit: 100})
		if err != nil {
			return err
		}
		for _, u := range users {
			if i := r.identityIndex(u); i >= 0 && !u.Blocked {
				if _, ok := r.seen[u.Identities[i].UserID]; !ok {
					missing = append(missing, u.UserID)
				}
			}
		}
		if len(users) < 100 {
			break
		}
	}
	for _, uid := range missing {
		err := r.Store.WithTx(r.ctx, func(tx store.Store) error {
			u, err := tx.Users().Get(r.ctx, tid, uid)
			if err != nil {
				return err
			}
			if !r.setActive(u, false) {
				return nil
			}
			u.UpdatedAt = r.now()
			if err := tx.Users().Update(r.ctx, u); err != nil {
				return err
			}
			return r.deactivate(tx, uid)
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			r.failures++
			r.log().WarnContext(r.ctx, "removed directory user not blocked", "tenant", tid, "connection", r.conn.ID, "error", err)
		}
	}
	return nil
}

// groups mirrors the selected (or all) Google groups as the connection's
// directory groups with their user members, and deletes the connection's
// groups no longer selected.
func (r *run) groups(p *store.DirectoryProvisioning, all bool) error {
	var targets []Group
	if all {
		if err := r.client.Groups(r.ctx, r.token, r.cfg.GoogleApps.Domain, func(g Group) error {
			targets = append(targets, g)
			return nil
		}); err != nil {
			return err
		}
	} else {
		selected, err := r.Store.DirectorySync().ListGroups(r.ctx, p.TenantID, p.ConnectionID)
		if err != nil {
			return err
		}
		for _, sg := range selected {
			g, err := r.client.Group(r.ctx, r.token, sg.GroupID)
			if err != nil {
				r.failures++
				continue
			}
			targets = append(targets, g)
		}
	}
	tid, d := r.conn.TenantID, r.Store.Directory()
	existing, _, err := d.ListGroups(r.ctx, tid, store.GroupFilter{ConnectionID: r.conn.ID}, store.Page{})
	if err != nil {
		return err
	}
	byExternal := map[string]*store.Group{}
	for _, g := range existing {
		byExternal[g.ExternalID] = g
	}
	keep := map[string]bool{}
	for _, g := range targets {
		if g.ID == "" {
			continue
		}
		keep[g.ID] = true
		if err := r.group(g, byExternal[g.ID]); err != nil {
			r.failures++
			r.log().WarnContext(r.ctx, "directory group not synchronized", "tenant", tid, "connection", r.conn.ID, "error", err)
		}
	}
	for _, g := range existing {
		if !keep[g.ExternalID] {
			if err := d.DeleteGroup(r.ctx, tid, g.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				r.failures++
			}
		}
	}
	return nil
}

func (r *run) group(g Group, cur *store.Group) error {
	tid, now := r.conn.TenantID, r.now()
	name := g.Name
	if !scim.ValidGroupName(name) {
		name = g.Email
	}
	if !scim.ValidGroupName(name) {
		return errors.New("group name unusable")
	}
	var members []string
	if err := r.client.Members(r.ctx, r.token, g.ID, func(m Member) error {
		if m.Type != "USER" || (m.Status != "" && m.Status != "ACTIVE") {
			return nil
		}
		sub := strings.ToLower(m.Email)
		if r.cfg.GoogleApps.MapUserIDToID {
			sub = m.ID
		}
		if uid, ok := r.seen[sub]; ok {
			members = append(members, uid)
		}
		return nil
	}); err != nil {
		return err
	}
	return r.Store.WithTx(r.ctx, func(tx store.Store) error {
		td := tx.Directory()
		if cur == nil {
			cur = &store.Group{TenantID: tid, ID: scim.NewGroupID(), ConnectionID: r.conn.ID, Name: name, ExternalID: g.ID, CreatedAt: now, UpdatedAt: now}
			if err := td.CreateGroup(r.ctx, cur); err != nil {
				return err
			}
		} else if cur.Name != name {
			cur.Name, cur.UpdatedAt = name, now
			if err := td.UpdateGroup(r.ctx, cur); err != nil {
				return err
			}
		}
		return td.UpdateGroupMembers(r.ctx, tid, cur.ID, members, nil, true, now)
	})
}
