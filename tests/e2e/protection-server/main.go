// This binary is only an e2e fixture. Production cmd/zeroauthy never imports it.
package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/config"
	"github.com/zeroauthy/zeroauthy/internal/email"
	"github.com/zeroauthy/zeroauthy/internal/keys"
	"github.com/zeroauthy/zeroauthy/internal/protection"
	"github.com/zeroauthy/zeroauthy/internal/seed"
	"github.com/zeroauthy/zeroauthy/internal/server"
	"github.com/zeroauthy/zeroauthy/internal/session"
	"github.com/zeroauthy/zeroauthy/internal/storage"
	"github.com/zeroauthy/zeroauthy/internal/system"
	"github.com/zeroauthy/zeroauthy/internal/tenant"
)

type rangeTransport struct{}

func (rangeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	digest := fmt.Sprintf("%X", sha1.Sum([]byte("M19-Breached-Password!")))
	body := strings.Repeat("0", 35) + ":0\r\n"
	if strings.HasSuffix(r.URL.Path, digest[:5]) {
		body = digest[5:] + ":1\r\n"
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

type verifier struct{}

func (verifier) Verify(_ context.Context, c protection.CaptchaChallenge, proof string) error {
	if c.ProviderID != "recaptcha_v2" || c.SiteKey != "m19-site" || !strings.HasPrefix(proof, "m19-valid-") {
		return protection.ErrCaptchaInvalid
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		panic(err)
	}
}
func run() error {
	ctx := context.Background()
	cfg, err := config.Load("tests/e2e/config.yaml", os.Environ())
	if err != nil {
		return err
	}
	st, err := storage.Open(ctx, cfg.Storage.DSN)
	if err != nil {
		return err
	}
	defer st.Close()
	if m, ok := st.(storage.Migrator); ok {
		if err = m.Migrate(ctx); err != nil {
			return err
		}
	}
	key, err := cfg.Security.MasterKeyBytes()
	if err != nil {
		return err
	}
	w, err := keys.NewLocalWrapper(key)
	if err != nil {
		return err
	}
	f, err := seed.Load(cfg.Seed)
	if err != nil {
		return err
	}
	f.Mode = seed.ModeCreateOnly
	if err = f.CheckManagementAPI(cfg.Server.BaseDomain); err != nil {
		return err
	}
	if err = seed.Apply(ctx, st, f, time.Now, w); err != nil {
		return err
	}
	host := tenant.SystemHost(cfg.Server.BaseDomain, cfg.Server.SystemHost)
	if _, err = system.Ensure(ctx, st, system.Config{Host: host, Wrapper: w}); err != nil {
		return err
	}
	log := slog.Default()
	if err = seed.InitializeProtection(ctx, st, cfg.Security, log); err != nil {
		return err
	}
	km := keys.NewManager(st.SigningKeys(), w)
	tenants, err := st.Tenants().List(ctx)
	if err != nil {
		return err
	}
	for _, tn := range tenants {
		if err = km.Ensure(ctx, tn.ID); err != nil {
			return err
		}
	}
	mail, err := email.New(cfg.Email, log)
	if err != nil {
		return err
	}
	p := &protection.Service{Store: st, Log: log, Wrapper: w, BreachChecker: protection.NewRangeChecker(rangeTransport{}), CaptchaVerifier: verifier{}}
	handler := server.New(server.Deps{Store: st, Keys: km, Wrapper: w, Resolver: tenant.NewResolver(st.Tenants(), cfg.Server.BaseDomain, false), Sessions: &session.Manager{Store: st}, Log: log, Mailer: mail, Protection: p, SystemHost: host})
	return http.ListenAndServeTLS(cfg.Server.Listen, cfg.Server.TLSCertFile, cfg.Server.TLSKeyFile, handler)
}
