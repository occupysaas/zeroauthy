// Package adhub serves AD/LDAP connections (Plan 38a, D-0160) through
// Auth0's open-source AD/LDAP Connector: the provisioning ticket the
// connector is installed with, the WebSocket hub it keeps open, and the
// requests zeroauthy sends it (login, password change, groups).
package adhub

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/httpx"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

// Paths served on tenant hosts.
const (
	TicketPrefix = "/p/ad/"
	HubPath      = "/ad-hub"
)

const (
	ticketLabel     = "zeroauthy/ad-ticket/v1"
	signingKeyLabel = "zeroauthy/ad-signing-key/v1"
	maxConfigBody   = 32 << 10
	ticketChars     = 32
)

// ErrUnavailable reports an ad connection that no connector serves, or a
// store without ad_hub.v1.
var ErrUnavailable = errors.New("adhub: connection not available")

// Service holds the AD/LDAP Connector state shared by the ticket routes, the
// hub and the Management API.
type Service struct {
	Store   store.Store
	Wrapper keys.Wrapper
	Log     *slog.Logger
	Now     func() time.Time
	// Hub, when set, is told when a registration evicts a certificate.
	Hub *Hub
	// TrustProxyHeaders lets X-Forwarded-Proto prove TLS (LR38a-2) and
	// X-Forwarded-For give the connector's address.
	TrustProxyHeaders bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// TicketHash is the lookup hash of a ticket.
func TicketHash(ticket string) string {
	sum := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(sum[:])
}

// RealmName is the realm of an ad connection: the aud of the connector's
// hub token and its WS-Fed audience (LR38a-7).
func RealmName(tn *store.Tenant, conn *store.Connection) string {
	return "urn:auth0:" + tn.Name + ":" + conn.Name
}

// Provision creates conn's ticket and signing key in tx (LR38a-4). conn must
// be an ad connection that has none yet.
func (s *Service) Provision(ctx context.Context, tx store.Store, conn *store.Connection) error {
	repo, err := store.ADHub(ctx, tx)
	if err != nil {
		return err
	}
	ticket := secrets.RandomString(ticketChars)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	fields := []string{conn.TenantID, conn.ID}
	sealedTicket, err := keys.SealBound(s.Wrapper, ticketLabel, fields, []byte(ticket))
	if err != nil {
		return err
	}
	sealedKey, err := keys.SealBound(s.Wrapper, signingKeyLabel, fields, []byte(base64.RawURLEncoding.EncodeToString(key)))
	if err != nil {
		return err
	}
	return repo.CreateADProvisioning(ctx, &store.ADProvisioning{
		TenantID: conn.TenantID, ConnectionID: conn.ID, TicketHash: TicketHash(ticket),
		TicketSealed: sealedTicket, SigningKeySealed: sealedKey, CreatedAt: s.now(),
	})
}

// TicketURL is conn's provisioning_ticket_url on host.
func (s *Service) TicketURL(ctx context.Context, host string, conn *store.Connection) (string, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return "", err
	}
	p, err := repo.GetADProvisioning(ctx, conn.TenantID, conn.ID)
	if err != nil {
		return "", err
	}
	ticket, err := keys.OpenBound(s.Wrapper, ticketLabel, []string{conn.TenantID, conn.ID}, p.TicketSealed)
	if err != nil {
		return "", err
	}
	return "https://" + host + TicketPrefix + string(ticket), nil
}

// SigningKey is conn's hub request key: the string the connector stores as
// TENANT_SIGNING_KEY and verifies HS256 tokens with.
func (s *Service) SigningKey(ctx context.Context, tenantID, connectionID string) ([]byte, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	p, err := repo.GetADProvisioning(ctx, tenantID, connectionID)
	if err != nil {
		return nil, err
	}
	return keys.OpenBound(s.Wrapper, signingKeyLabel, []string{tenantID, connectionID}, p.SigningKeySealed)
}

// ticketConnection resolves a ticket on the request's tenant host.
func (s *Service) ticketConnection(ctx context.Context, res tenant.Resolved, ticket string) (*store.Connection, error) {
	if ticket == "" || len(ticket) > 128 {
		return nil, store.ErrNotFound
	}
	repo, err := store.ADHub(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	p, err := repo.FindADProvisioning(ctx, res.Tenant.ID, TicketHash(ticket))
	if err != nil {
		return nil, err
	}
	conn, err := s.Store.Connections().Get(ctx, p.TenantID, p.ConnectionID)
	if err != nil {
		return nil, err
	}
	if conn.Strategy != store.StrategyAD {
		return nil, store.ErrNotFound
	}
	return conn, nil
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (s *Service) ticketFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown provisioning ticket")
		return
	}
	s.log().ErrorContext(r.Context(), "ad provisioning ticket", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "server_error", "the provisioning ticket could not be read")
}

// TicketInfo answers GET /p/ad/{ticket}/info (lib/provisioningTicket.js).
func (s *Service) TicketInfo(w http.ResponseWriter, r *http.Request, ticket string) {
	noStore(w)
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
		return
	}
	conn, err := s.ticketConnection(r.Context(), res, ticket)
	if err != nil {
		s.ticketFail(w, r, err)
		return
	}
	domain, _ := conn.Extra["tenant_domain"].(string)
	if domain == "" {
		domain = strings.Split(res.Host, ":")[0]
	}
	certAuth, _ := conn.Extra["certAuth"].(bool)
	kerberos, _ := conn.Extra["kerberos"].(bool)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"adHub":            "wss://" + res.Host + HubPath,
		"connectionName":   conn.Name,
		"connectionDomain": domain,
		"certAuth":         certAuth,
		"kerberos":         kerberos,
		"realm":            map[string]any{"name": RealmName(res.Tenant, conn), "postTokenUrl": res.Origin() + "/login/callback"},
	})
}

type registration struct {
	Certs          []string `json:"certs"`
	SignInEndpoint *string  `json:"signInEndpoint"`
	AgentMode      *bool    `json:"agentMode"`
	AgentVersion   *string  `json:"agentVersion"`
}

// TicketConfigure answers POST /p/ad/{ticket} (lib/configureConnection.js):
// the connector registers its certificate and receives the signing key.
func (s *Service) TicketConfigure(w http.ResponseWriter, r *http.Request, ticket string) {
	noStore(w)
	res, ok := tenant.FromContext(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "unknown tenant")
		return
	}
	ctx := r.Context()
	conn, err := s.ticketConnection(ctx, res, ticket)
	if err != nil {
		s.ticketFail(w, r, err)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxConfigBody))
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "the body is too large or unreadable")
		return
	}
	var reg registration
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&reg); err != nil || len(reg.Certs) != 1 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "certs must hold the connector certificate")
		return
	}
	cert, err := rules.ParseADCert(reg.Certs[0])
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "certs[0] is not a certificate")
		return
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || pub.N.BitLen() < 2048 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "the connector certificate must hold an RSA key of at least 2048 bits")
		return
	}
	if reg.SignInEndpoint != nil {
		u, err := url.Parse(*reg.SignInEndpoint)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || len(*reg.SignInEndpoint) > 2048 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "signInEndpoint must be an http or https URL")
			return
		}
	}
	if reg.AgentVersion != nil && (len(*reg.AgentVersion) > 32 || strings.ContainsAny(*reg.AgentVersion, "\x00\r\n")) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "agentVersion must be at most 32 bytes")
		return
	}
	der := base64.StdEncoding.EncodeToString(cert.Raw)
	var kept []string
	err = s.Store.WithTx(ctx, func(tx store.Store) error {
		cur, err := tx.Connections().Get(ctx, conn.TenantID, conn.ID)
		if err != nil {
			return err
		}
		if cur.Strategy != store.StrategyAD {
			return store.ErrNotFound
		}
		next := *cur
		next.Extra = cloneExtra(cur.Extra)
		certs := []string{der}
		for _, c := range anyStrings(cur.Extra["certs"]) {
			if c != der && len(certs) < rules.MaxADCerts {
				certs = append(certs, c)
			}
		}
		var t1, t384 []any
		for _, c := range certs {
			parsed, err := rules.ParseADCert(c)
			if err != nil {
				continue
			}
			a, b := rules.ADFSThumbprints(parsed.Raw)
			t1, t384 = append(t1, a), append(t384, b)
			kept = append(kept, a)
		}
		next.Extra["certs"] = stringsAny(certs)
		next.Extra["thumbprints"] = t1
		next.Extra["thumbprints_sha384"] = t384
		if reg.SignInEndpoint != nil {
			next.Extra["signInEndpoint"] = *reg.SignInEndpoint
		}
		if reg.AgentMode != nil {
			next.Extra["agentMode"] = *reg.AgentMode
		}
		if reg.AgentVersion != nil {
			next.Extra["agentVersion"] = *reg.AgentVersion
		}
		return tx.Connections().Update(ctx, &next)
	})
	if err != nil {
		s.ticketFail(w, r, err)
		return
	}
	key, err := s.SigningKey(ctx, conn.TenantID, conn.ID)
	if err != nil {
		s.ticketFail(w, r, err)
		return
	}
	if s.Hub != nil {
		s.Hub.Evict(conn.TenantID, conn.ID, kept)
	}
	s.log().InfoContext(ctx, "ad connector registered", "tenant", conn.TenantID, "connection", conn.Name)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"signingKey": string(key)})
}

func cloneExtra(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+4)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func anyStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = slices.Clone(t)
	}
	return out
}

func stringsAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// SessionLiveness is how long a hub session row counts as alive after its
// last heartbeat.
const SessionLiveness = 90 * time.Second

// Online reports whether a connector serves conn on any replica.
func (s *Service) Online(ctx context.Context, conn *store.Connection) (bool, error) {
	repo, err := store.ADHub(ctx, s.Store)
	if errors.Is(err, store.ErrADHubUnavailable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	list, err := repo.ListADHubSessions(ctx, conn.TenantID, conn.ID, s.now().Add(-SessionLiveness))
	return len(list) > 0, err
}
