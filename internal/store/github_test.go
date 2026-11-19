package store

import (
	"errors"
	"testing"
)

func TestGitHubPublicID(t *testing.T) {
	if got := FederatedPublicID("github", "gh", "12345"); got != "github|12345" {
		t.Fatalf("public id %q", got)
	}
	id := Identity{Provider: "github", Connection: "gh", UserID: "12345"}
	sub, ok, err := id.FederatedSubject()
	if sub != "12345" || !ok || err != nil {
		t.Fatalf("subject %q %v %v", sub, ok, err)
	}
}

// An imported GitHub identity must carry the canonical decimal ID that a
// login produces, or it would be indexed under a subject no login can match.
func TestGitHubImportRejectsNonCanonicalSubject(t *testing.T) {
	resolve := func(userID string) ([]FederatedIdentityKey, error) {
		u := &User{TenantID: "ten", Identities: []Identity{{Provider: "github", Connection: "gh", UserID: userID}}}
		return ResolveFederatedKeys(u, func(string) (*Connection, error) {
			return &Connection{ID: "con", Name: "gh", Strategy: "github"}, nil
		})
	}
	for _, bad := range []string{"0123", "1e3", "+1", "-1", "0", "9223372036854775808", "gh|12", " 1", "1 ", "1.0", "0x1F", "١٢"} {
		t.Run(bad, func(t *testing.T) {
			if keys, err := resolve(bad); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted %q: %+v %v", bad, keys, err)
			}
		})
	}
	for _, good := range []string{"1", "42", "9007199254740993", "9223372036854775807"} {
		t.Run(good, func(t *testing.T) {
			keys, err := resolve(good)
			if err != nil || len(keys) != 1 || keys[0] != (FederatedIdentityKey{TenantID: "ten", ConnectionID: "con", Subject: good}) {
				t.Fatalf("keys %+v %v", keys, err)
			}
		})
	}
}
