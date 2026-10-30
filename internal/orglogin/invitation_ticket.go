package orglogin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// InvitationTicket is recoverable only for authorized management and delivery.
// Never persist or log this plaintext value.
type InvitationTicket struct {
	TicketID string `json:"ticket_id"`
	URL      string `json:"invitation_url"`
}

const invitationTicketLabel = "organization-invitation/v1"

func BuildInvitationURL(loginURI, ticket, orgID, orgName string) (string, error) {
	u, err := url.Parse(loginURI)
	if len(loginURI) > 2048 || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("organization invitation requires an HTTPS login URI")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", errors.New("invalid invitation login query")
	}
	q.Set("invitation", ticket)
	q.Set("organization", orgID)
	q.Set("organization_name", orgName)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func InvitationTicketHash(ticket string) string {
	s := sha256.Sum256([]byte(ticket))
	return hex.EncodeToString(s[:])
}
func IssueInvitationTicket(w keys.Wrapper, in *store.OrganizationInvitation, loginURI, orgName string) (InvitationTicket, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return InvitationTicket{}, err
	}
	data := InvitationTicket{TicketID: base64.RawURLEncoding.EncodeToString(b[:])}
	var err error
	data.URL, err = BuildInvitationURL(loginURI, data.TicketID, in.OrganizationID, orgName)
	if err != nil {
		return InvitationTicket{}, err
	}
	plain, _ := json.Marshal(data)
	in.WrappedTicket, err = keys.SealBound(w, invitationTicketLabel, []string{in.TenantID, in.OrganizationID, in.ID}, plain)
	if err != nil {
		return InvitationTicket{}, err
	}
	in.TicketHash = InvitationTicketHash(data.TicketID)
	return data, nil
}
func OpenInvitationTicket(w keys.Wrapper, in *store.OrganizationInvitation) (InvitationTicket, error) {
	var out InvitationTicket
	plain, err := keys.OpenBound(w, invitationTicketLabel, []string{in.TenantID, in.OrganizationID, in.ID}, in.WrappedTicket)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(plain, &out) != nil || out.TicketID == "" || out.URL == "" || InvitationTicketHash(out.TicketID) != in.TicketHash {
		return InvitationTicket{}, errors.New("invalid invitation envelope")
	}
	return out, nil
}
