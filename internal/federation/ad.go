package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/access"
	"github.com/zeroauthy/zeroauthy/internal/connrules"
	"github.com/zeroauthy/zeroauthy/internal/federation/rules"
	"github.com/zeroauthy/zeroauthy/internal/orglogin"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// StrategyAD is the AD/LDAP connection strategy (Plan 38a): username and
// password are checked by Auth0's AD/LDAP Connector (internal/adhub).
const StrategyAD = rules.AD

// ADUsernameKey is the identity provider data key that keeps the name the
// user signed in with: the connector looks users up by it
// (LDAP_USER_BY_NAME), so password changes send it back.
const ADUsernameKey = "ad_username"

// adRootKeys are the connector profile members mapped to the root profile;
// every other member is identity provider data.
var adRootKeys = []string{"id", "displayName", "name", "nickname", "emails", "email", "email_verified", "picture"}

// ADProfile maps a connector profile (lib/defaultProfileMapping.js or a
// customer's mapper) to a Profile (LR38a-8): id is the subject, displayName
// the name, name.givenName and name.familyName the given and family names,
// nickname, the first emails value (or email) the email, verified only when
// the profile says email_verified true. The other members, groups among
// them, and the sign-in name are identity provider data.
func ADProfile(raw json.RawMessage, username string) (Profile, error) {
	if len(raw) > maxProfileBytes {
		return Profile{}, fmt.Errorf("%w: larger than %d bytes", ErrProfile, maxProfileBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return Profile{}, fmt.Errorf("%w: not a JSON object", ErrProfile)
	}
	var sub string
	switch v := m["id"].(type) {
	case string:
		sub = v
	case json.Number:
		sub = v.String()
	}
	if sub == "" {
		return Profile{}, fmt.Errorf("%w: the connector profile has no id", ErrProfile)
	}
	claims := map[string]any{}
	if v, ok := m["displayName"].(string); ok && v != "" {
		claims["name"] = v
	}
	if n, ok := m["name"].(map[string]any); ok {
		if v, ok := n["givenName"].(string); ok && v != "" {
			claims["given_name"] = v
		}
		if v, ok := n["familyName"].(string); ok && v != "" {
			claims["family_name"] = v
		}
	}
	if v, ok := m["nickname"].(string); ok && v != "" {
		claims["nickname"] = v
	}
	email, _ := m["email"].(string)
	if list, ok := m["emails"].([]any); ok && len(list) > 0 {
		if first, ok := list[0].(map[string]any); ok {
			if v, ok := first["value"].(string); ok {
				email = v
			}
		}
	}
	if email != "" {
		claims["email"] = strings.ToLower(email)
		claims["email_verified"] = m["email_verified"] == true
	}
	if v, ok := m["picture"].(string); ok && v != "" {
		claims["picture"] = v
	}
	p, err := profileFromClaims(sub, claims)
	if err != nil {
		return Profile{}, err
	}
	p.ProviderData = nil
	extra := map[string]any{}
	for k, v := range m {
		if !slices.Contains(adRootKeys, k) && v != nil && !strings.HasPrefix(k, "__") && k != "constructor" && k != "prototype" {
			extra[k] = v
		}
	}
	if username != "" {
		extra[ADUsernameKey] = username
	}
	if enc, err := json.Marshal(extra); err == nil && len(enc) <= maxProfileBytes && len(extra) > 0 {
		p.ProviderData = extra
	}
	return p, nil
}

// DirectLoginInput is a username/password login through an ad connection
// whose credentials the connector has already accepted.
type DirectLoginInput struct {
	Tenant     *store.Tenant
	Txn        *store.AuthTransaction
	Connection *store.Connection
	Profile    Profile
}

// DirectLogin provisions or synchronizes the user of an accepted ad login,
// with the same identity and organization rules as a federated callback.
func (s *FlowService) DirectLogin(ctx context.Context, in DirectLoginInput) (*store.User, error) {
	if in.Tenant == nil || in.Txn == nil || in.Connection == nil || in.Connection.Strategy != StrategyAD {
		return nil, ErrConnectionUnusable
	}
	var out *store.User
	commit := func() error {
		return orglogin.WithMembershipEvents(ctx, s.Store, func(ctx context.Context, tx store.Store) error {
			conn, err := tx.Connections().Get(ctx, in.Tenant.ID, in.Connection.ID)
			if errors.Is(err, store.ErrNotFound) || err == nil && conn.Strategy != StrategyAD {
				return ErrConnectionUnusable
			}
			if err != nil {
				return err
			}
			client, err := tx.Clients().Get(ctx, in.Tenant.ID, in.Txn.ClientID)
			if errors.Is(err, store.ErrNotFound) || err == nil && !access.ConnectionUsable(client, conn) {
				return ErrConnectionUnusable
			}
			if err != nil {
				return err
			}
			if cfg, err := ParseConfig(*connrules.FromConnection(conn)); err != nil || !cfg.AuthenticationActive {
				return ErrConnectionUnusable
			}
			user, _, err := s.resolveIdentity(ctx, tx, conn, ProviderResult{Profile: in.Profile}, nil)
			if err != nil {
				return err
			}
			oc, err := orglogin.Load(ctx, tx, in.Tenant.ID, in.Txn.Params)
			if err != nil {
				return err
			}
			if oc.Org != nil {
				err = orglogin.CheckMemberClient(ctx, tx, in.Tenant.ID, oc.Org.ID, in.Txn.ClientID)
			}
			if err == nil && in.Txn.Params[orglogin.InvitationIDParam] == "" {
				err = orglogin.CheckMembership(ctx, tx, oc, user.UserID, conn.ID)
			}
			if err != nil && !errors.Is(err, orglogin.ErrNotMember) {
				return err
			}
			out = user
			return nil
		})
	}
	err := commit()
	if errors.Is(err, store.ErrConflict) {
		err = commit() // a concurrent first login provisioned the user
	}
	return out, err
}

// KerberosRedirect reports whether a login for conn from clientIP on host
// goes to the connector's Windows integrated sign-in (Plan 38a §5): kerberos
// on, the client in ips, a registered connector endpoint and certificates,
// and the host the connector posts tokens to (LR38a-10).
func KerberosRedirect(tenant *store.Tenant, conn *store.Connection, host, clientIP string) bool {
	if conn == nil || conn.Strategy != StrategyAD || tenant == nil || host != tenant.CanonicalHost {
		return false
	}
	cfg, err := parseConnConfig(conn)
	if err != nil || cfg.AD == nil || cfg.ADFS == nil || !cfg.AuthenticationActive {
		return false
	}
	return rules.ADClientInRanges(clientIP, cfg.AD.IPs)
}
