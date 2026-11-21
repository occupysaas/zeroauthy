// prepare provisions throwaway conformance profile and MFA data in the local
// SQLite fixture. It is a test harness, never a zeroauthy runtime command.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/mfa"
	"github.com/zeroauthy/zeroauthy/internal/secrets"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/store"
	"github.com/zeroauthy/zeroauthy/internal/store/sqlstore"
	"os"
	"strings"
	"time"
)

type fixtureInput struct {
	RecoveryBasic    string `json:"recovery_basic"`
	RecoveryFormpost string `json:"recovery_formpost"`
}

func prepare(ctx context.Context, st store.Store, wrapper keys.Wrapper, name string, input fixtureInput, now time.Time) error {
	if name != "conformance" && name != "certification" || len(input.RecoveryBasic) < 24 || len(input.RecoveryFormpost) < 24 {
		return store.ErrInvalid
	}
	return st.WithTx(ctx, func(tx store.Store) error {
		tenant, err := tx.Tenants().GetByName(ctx, name)
		if err != nil {
			return err
		}
		g, err := tx.MFA().GetGuardian(ctx, tenant.ID)
		if err != nil {
			return err
		}
		g.Factors = map[string]bool{"otp": true, "recovery-code": true}
		g.Policies = nil
		if err := tx.MFA().PutGuardian(ctx, g, g.Version); err != nil {
			return err
		}
		for i, email := range []string{"conformance@example.com", "acr-basic@example.com", "acr-formpost@example.com"} {
			u, err := tx.Users().FindByLogin(ctx, tenant.ID, "Username-Password-Authentication", email)
			if err != nil {
				return err
			}
			own := u.OwnIdentity()
			if own == nil {
				return store.ErrInvalid
			}
			own.ProviderData = map[string]any{"middle_name": "Test", "preferred_username": "conformance", "profile": "https://example.com/conformance", "website": "https://example.com/", "gender": "unspecified", "birthdate": "2000-01-01", "zoneinfo": "UTC", "locale": "en", "address": map[string]any{"formatted": "1 Test Street, Example", "street_address": "1 Test Street", "locality": "Example", "region": "Test", "postal_code": "00000", "country": "US"}}
			u.Picture = "https://example.com/avatar.png"
			u.PhoneNumber = fmt.Sprintf("+1202555010%d", i)
			u.PhoneVerified = true
			u.PhoneNormalized = u.PhoneNumber
			if err := tx.Users().Update(ctx, u); err != nil {
				return err
			}
			if i == 0 {
				continue
			}
			if err := tx.MFA().DeleteUserMFA(ctx, tenant.ID, u.UserID); err != nil {
				return err
			}
			a := &store.Authenticator{TenantID: tenant.ID, UserID: u.UserID, ID: "totp|fixture_" + secrets.RandomString(20), Type: "totp", Confirmed: true, LastStep: -1, CreatedAt: now}
			a.SealedSecret, err = mfa.SealTOTPSecret(wrapper, tenant.ID, u.UserID, a.ID, mfa.NewTOTPSecret())
			if err != nil {
				return err
			}
			if err := tx.MFA().CreateAuthenticator(ctx, a); err != nil {
				return err
			}
			code := input.RecoveryBasic
			if i == 2 {
				code = input.RecoveryFormpost
			}
			if err := tx.MFA().ReplaceRecoveryCode(ctx, tenant.ID, u.UserID, "", secrets.HashToken(mfa.NormalizeRecoveryCode(code)), now); err != nil {
				return err
			}
		}
		return nil
	})
}
func run() error {
	dsn := flag.String("dsn", "", "throwaway SQLite fixture DSN")
	seedPath := flag.String("seed", "", "seed file")
	fixturePath := flag.String("fixtures", "", "private generated fixture JSON")
	tenantName := flag.String("tenant", "conformance", "conformance or certification")
	flag.Parse()
	if !strings.HasPrefix(*dsn, "sqlite://") {
		return errors.New("SQLite fixture DSN required")
	}
	key, err := base64.StdEncoding.DecodeString(os.Getenv("ZEROAUTHY_SECURITY__MASTER_KEY"))
	if err != nil {
		return errors.New("fixture master key required")
	}
	wrapper, err := keys.NewLocalWrapper(key)
	clear(key)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*seedPath)
	if err != nil {
		return err
	}
	f, err := seed.Parse(raw)
	if err != nil {
		return err
	}
	raw, err = os.ReadFile(*fixturePath)
	if err != nil {
		return err
	}
	var input fixtureInput
	if json.Unmarshal(raw, &input) != nil {
		return store.ErrInvalid
	}
	ctx := context.Background()
	st, err := sqlstore.Open(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}
	if err := seed.Apply(ctx, st, f, time.Now, wrapper); err != nil {
		return err
	}
	return prepare(ctx, st, wrapper, *tenantName, input, time.Now().UTC())
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "conformance fixture preparation failed; check private inputs and storage")
		os.Exit(1)
	}
}
