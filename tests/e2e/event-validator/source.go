package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/federation"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
)

// seedSource creates representative protected input using the actual store and
// encryption contracts. It intentionally bypasses event capture during setup.
func seedSource(work, userID, token string) error {
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, "sqlite://"+filepath.Join(work, "events.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	tenant, err := st.Tenants().GetByName(ctx, "events")
	if err != nil {
		return err
	}
	user, err := st.Users().Get(ctx, tenant.ID, userID)
	if err != nil {
		return err
	}
	hashes := []string{}
	for _, id := range user.Identities {
		if strings.HasPrefix(id.PasswordHash, "$argon2id$") {
			hashes = append(hashes, id.PasswordHash)
		}
	}
	if len(hashes) == 0 {
		return fmt.Errorf("source credential positive control missing")
	}
	conn, err := st.Connections().GetByName(ctx, tenant.ID, "fixture-upstream")
	if err != nil {
		return err
	}
	user.Identities = append(user.Identities, store.Identity{Connection: conn.Name, Provider: conn.Strategy, UserID: "upstream32", ProfileData: map[string]any{"email": "upstream@e2e.local", "email_verified": true}})
	if err = st.Users().Update(ctx, user); err != nil {
		return err
	}
	encoded, err := os.ReadFile(filepath.Join(work, "master.key"))
	if err != nil {
		return err
	}
	master, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return err
	}
	wrapper, err := keys.NewLocalWrapper(master)
	if err != nil {
		return err
	}
	key := store.FederatedIdentityKey{TenantID: tenant.ID, ConnectionID: conn.ID, Subject: "upstream32"}
	sealed, err := federation.SealTokens(wrapper, key, federation.TokenSet{AccessToken: token, TokenType: "Bearer"})
	if err != nil {
		return err
	}
	if err = st.Federation().PutTokens(ctx, key, sealed); err != nil {
		return err
	}
	stored, err := st.Federation().GetTokens(ctx, key)
	if err != nil {
		return err
	}
	opened, err := federation.OpenTokens(wrapper, key, stored)
	if err != nil {
		return err
	}
	if opened.AccessToken != token {
		return fmt.Errorf("source token positive control failed")
	}
	// Sensitive hashes are emitted only to the caller's private state file.
	return json.NewEncoder(os.Stdout).Encode(hashes)
}
