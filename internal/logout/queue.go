package logout

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/zeroauthy/zeroauthy/internal/clientrules"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"net/url"
	"strings"
	"time"
)

const JobKind = "backchannel-logout"
const envelopeLabel = "backchannel-logout/v1"

type Initiator string

const (
	RPLogout               Initiator = "rp-logout"
	IDPLogout              Initiator = "idp-logout"
	PasswordChanged        Initiator = "password-changed"
	SessionExpired         Initiator = "session-expired"
	SessionRevoked         Initiator = "session-revoked"
	AccountDeleted         Initiator = "account-deleted"
	EmailIdentifierChanged Initiator = "email-identifier-changed"
)

type payload struct {
	Issuer, ClientID, URL string
	Initiator             Initiator
	Session               store.LoginSession
	IncludeMetadata       bool
	Deadline              time.Time
}

func (s *Service) WithStore(st store.Store) *Service { copy := *s; copy.Store = st; return &copy }
func subscribed(settings *store.OIDCLogout, why Initiator) bool {
	if settings == nil || len(settings.BackchannelURLs) != 1 {
		return false
	}
	normalized := settings.Clone()
	if clientrules.NormalizeOIDCLogout(normalized) != nil {
		return false
	}
	if normalized.InitiatorsMode == "all" {
		return true
	}
	for _, initiator := range normalized.Initiators {
		if initiator == string(why) {
			return true
		}
	}
	return false
}

// SessionsEnded enqueues sealed immutable delivery snapshots through the
// caller's transactional Store. Local termination and enqueue must commit
// together; this function performs no network calls.
func (s *Service) SessionsEnded(ctx context.Context, tid string, sessions []*store.LoginSession, why Initiator) error {
	if s == nil || s.Store == nil || s.Wrapper == nil {
		return store.ErrInvalid
	}
	if why != RPLogout && why != IDPLogout && why != PasswordChanged && why != SessionExpired && why != SessionRevoked && why != AccountDeleted && why != EmailIdentifierChanged {
		return store.ErrInvalid
	}
	tenant, err := s.Store.Tenants().Get(ctx, tid)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, session := range sessions {
		if session == nil || session.TenantID != tid || session.ID == "" || session.UserID == "" {
			return store.ErrInvalid
		}
		issuer := "https://" + tenant.CanonicalHost + "/"
		if session.Origin != "" {
			issuer = strings.TrimSuffix(session.Origin, "/") + "/"
		}
		parsed, err := url.Parse(issuer)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
			// Invalid historical issuer affects this notification only.
			continue
		}
		owner, err := s.Store.Tenants().GetByDomain(ctx, parsed.Host)
		if err != nil || owner == nil || owner.ID != tid {
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			// A retired or reassigned domain must not prevent local revocation.
			continue
		}
		for _, id := range session.ClientIDs {
			unique := session.ID + "\x00" + id
			if seen[unique] {
				continue
			}
			seen[unique] = true
			client, err := s.Store.Clients().Get(ctx, tid, id)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if !subscribed(client.OIDCLogout, why) {
				continue
			}
			settings := client.OIDCLogout
			snapshot := store.LoginSession{TenantID: tid, ID: session.ID, UserID: session.UserID, ClientIDs: []string{id}}
			include := settings.IncludeSessionMetadata != nil && *settings.IncludeSessionMetadata
			if include {
				snapshot.Metadata = session.Metadata
			}
			now := s.now()
			receiver := settings.BackchannelURLs[0]
			if strings.Contains(receiver, "{organization_") {
				orgID := session.ClientOrganizations[id]
				if orgID != "" {
					org, err := s.Store.Organizations().Get(ctx, tid, orgID)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return err
					}
					if err == nil {
						receiver = strings.NewReplacer("{organization_id}", url.PathEscape(org.ID), "{organization_name}", url.PathEscape(org.Name)).Replace(receiver)
					}
				}
			}
			content := payload{Issuer: issuer, ClientID: id, URL: receiver, Initiator: why, Session: snapshot, IncludeMetadata: include, Deadline: now.Add(10 * time.Minute)}
			raw, err := json.Marshal(content)
			if err != nil {
				return err
			}
			job := &store.ActionJob{TenantID: tid, ID: "bcl_" + secrets.RandomString(32), Trigger: JobKind, Status: "pending", NextAt: now, CreatedAt: now, UpdatedAt: now}
			job.Sealed, err = keys.SealBound(s.Wrapper, envelopeLabel, []string{tid, job.ID, JobKind}, raw)
			if err != nil {
				return err
			}
			if err := s.Store.Actions().EnqueueJob(ctx, job); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Service) open(job *store.ActionJob) (*payload, error) {
	if job == nil || job.Trigger != JobKind {
		return nil, store.ErrInvalid
	}
	raw, err := keys.OpenBound(s.Wrapper, envelopeLabel, []string{job.TenantID, job.ID, JobKind}, job.Sealed)
	if err != nil {
		return nil, store.ErrInvalid
	}
	var out payload
	if json.Unmarshal(raw, &out) != nil || out.Session.TenantID != job.TenantID || out.Session.ID == "" || out.ClientID == "" || out.Deadline.IsZero() {
		return nil, store.ErrInvalid
	}
	return &out, nil
}

// EndUserSessions is called inside the transaction changing credentials or
// account state. The snapshot is retained before deleting the local sessions.
func (s *Service) EndUserSessions(ctx context.Context, tid, uid string, why Initiator) error {
	if _, err := s.Store.Tenants().Get(ctx, tid); err != nil {
		return err
	}
	ended, err := s.Store.Sessions().ListByUser(ctx, tid, uid)
	if err != nil {
		return err
	}
	if _, err := s.Store.Sessions().DeleteByUser(ctx, tid, uid); err != nil {
		return err
	}
	return s.SessionsEnded(ctx, tid, ended, why)
}
