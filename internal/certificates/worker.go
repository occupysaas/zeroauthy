package certificates

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

const (
	leaseDuration  = 120 * time.Second
	heartbeatEvery = 30 * time.Second
	recordTTL      = 24 * time.Hour // order and challenge records
	maxBackoff     = 6 * time.Hour
	initialFailed  = 5 // failed attempts before initial issuance shows failed
	pollInterval   = 500 * time.Millisecond
	pollAttempts   = 240
)

// Prover re-checks domain ownership before every issuance (customdomain.Service).
type Prover interface {
	ProveOwnership(ctx context.Context, d *store.CustomDomain) error
}

// WorkerConfig is per-process worker policy.
type WorkerConfig struct {
	Owner     string // lease owner; unique per process
	Email     string
	Challenge string         // http-01 or tls-alpn-01
	Roots     *x509.CertPool // trust for issued chains
	Workers   int            // concurrent resources per process (default 2)
	Poll      time.Duration  // due scan interval (default 30s)
	Hosted    *HostedConfig  // nil: no hosted wildcard
}

// Worker issues and renews managed domain certificates. Leases with fencing
// serialize work per resource across replicas; no transaction spans CA or
// DNS calls, and every write after a network step re-checks the lease.
type Worker struct {
	m      *Manager
	ca     CA
	prover Prover
	cfg    WorkerConfig

	mu             sync.Mutex
	hostedFailures int       // consecutive hosted wildcard failures
	hostedNext     time.Time // hosted backoff (per process; leases serialize)
}

func NewWorker(m *Manager, ca CA, prover Prover, cfg WorkerConfig) *Worker {
	if cfg.Workers < 1 {
		cfg.Workers = 2
	}
	if cfg.Poll <= 0 {
		cfg.Poll = 30 * time.Second
	}
	return &Worker{m: m, ca: ca, prover: prover, cfg: cfg}
}

// DomainResource is the lease and order key of a domain generation.
func DomainResource(d *store.CustomDomain) string {
	return fmt.Sprintf("domain/%s/%s/%d", d.TenantID, d.ID, d.Generation)
}

func parseDomainResource(key string) (tenantID, id string, gen int64, ok bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "domain" {
		return "", "", 0, false
	}
	gen, err := strconv.ParseInt(parts[3], 10, 64)
	return parts[1], parts[2], gen, err == nil && parts[1] != "" && parts[2] != ""
}

// RenewalTime is two-thirds into the certificate's lifetime plus a
// deterministic per-resource jitter below 5% of the lifetime.
func RenewalTime(resource string, notBefore, notAfter time.Time) time.Time {
	life := notAfter.Sub(notBefore)
	sum := sha256.Sum256([]byte(resource))
	frac := float64(binary.BigEndian.Uint64(sum[:8])>>11) / float64(1<<53)
	return notBefore.Add(life*2/3 + time.Duration(frac*0.05*float64(life)))
}

// Run scans for due domains and cleans up expired order/challenge records
// until ctx ends, then waits for in-flight work, which the cancellation stops.
func (w *Worker) Run(ctx context.Context) {
	sem := make(chan struct{}, w.cfg.Workers)
	var wg sync.WaitGroup
	defer wg.Wait()
	busy := sync.Map{}
	tick := time.NewTicker(w.cfg.Poll)
	defer tick.Stop()
	for {
		due, err := w.m.st.CustomDomains().ListDue(ctx, 100)
		if err == nil {
			for _, d := range due {
				if !w.due(d) {
					continue
				}
				key := DomainResource(d)
				if _, running := busy.LoadOrStore(key, true); running {
					continue
				}
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					busy.Delete(key)
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() { <-sem; busy.Delete(key) }()
					_ = w.Reconcile(ctx, key)
				}()
			}
		}
		if h := w.cfg.Hosted; h != nil {
			key := HostedResource(w.m.cfg.DeploymentID, h.BaseDomain)
			if _, running := busy.LoadOrStore(key, true); !running {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer busy.Delete(key)
					_ = w.Reconcile(ctx, key)
				}()
			}
		}
		w.cleanup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (w *Worker) due(d *store.CustomDomain) bool {
	if d.Type != customdomain.TypeManaged {
		return false
	}
	switch d.Lifecycle {
	case customdomain.LifecycleIssuing, customdomain.LifecycleActive, customdomain.LifecycleRenewalError:
		return d.NextAttemptAt != nil && !w.m.clock().Before(*d.NextAttemptAt)
	}
	return false
}

// cleanup removes expired order and challenge records (bounded to 24h).
func (w *Worker) cleanup(ctx context.Context) {
	rows, err := w.m.st.TLSAssets().ListExpired(ctx, 100)
	if err != nil {
		return
	}
	for _, a := range rows {
		switch a.Kind {
		case store.TLSAssetOrder, store.TLSAssetChallenge:
			_ = w.m.st.TLSAssets().Delete(ctx, a.Key, a.Revision)
		case store.TLSAssetDNSIntent:
			// Remove a record we created before forgetting it; ambiguous or
			// pre-existing records are never deleted.
			if h := w.cfg.Hosted; h != nil && a.PublicData.Status == "created" {
				rec := DNSRecord{ID: a.PublicData.DNSRecordID, Zone: h.Zone, Name: a.PublicData.RecordName, Value: a.PublicData.RecordValue, Created: true}
				if err := h.Provider.CleanUp(ctx, rec); err != nil {
					continue
				}
			}
			_ = w.m.st.TLSAssets().Delete(ctx, a.Key, a.Revision)
		}
	}
}

// errStale means the lease or the domain generation changed under us.
var errStale = errors.New("certificates: work is stale")

// Reconcile works one resource if its lease is free; a held lease is not an
// error. Failures are recorded on the domain with a safe message and backoff.
func (w *Worker) Reconcile(ctx context.Context, key string) error {
	if strings.HasPrefix(key, "hosted/") {
		return w.reconcileHosted(ctx, key)
	}
	tenantID, id, gen, ok := parseDomainResource(key)
	if !ok {
		return fmt.Errorf("certificates: unknown resource %q", key)
	}
	return w.withLease(ctx, key, func(ctx context.Context, lease store.TLSLease) error {
		d, err := w.m.st.CustomDomains().Get(ctx, tenantID, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.Generation != gen || !w.due(d) && d.Lifecycle != customdomain.LifecycleIssuing {
			return nil
		}
		if err := w.issue(ctx, lease, d); err != nil {
			if !errors.Is(err, errStale) {
				w.fail(context.WithoutCancel(ctx), lease, d, err)
			}
			return err
		}
		return nil
	})
}

// withLease runs fn while holding key's lease, renewing it every 30s and
// cancelling fn's context if renewal fails. A held lease is not an error.
func (w *Worker) withLease(ctx context.Context, key string, fn func(context.Context, store.TLSLease) error) error {
	lease, err := w.m.st.TLSAssets().ClaimLease(ctx, key, w.cfg.Owner, leaseDuration)
	if errors.Is(err, store.ErrConflict) {
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	beat := make(chan struct{})
	go func() {
		defer close(beat)
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := w.m.st.TLSAssets().RenewLease(ctx, *lease, leaseDuration); err != nil {
					cancel() // lost the lease: stop all work
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		<-beat
		_ = w.m.st.TLSAssets().ReleaseLease(context.Background(), *lease)
	}()
	return fn(ctx, *lease)
}

func (w *Worker) issue(ctx context.Context, lease store.TLSLease, d *store.CustomDomain) error {
	if err := w.prover.ProveOwnership(ctx, d); err != nil {
		return err
	}
	acct, accountURL, err := w.account(ctx)
	if err != nil {
		return err
	}
	names := []string{d.Domain}
	t := target{resource: DomainResource(d), tenantID: d.TenantID, domainID: d.ID, gen: d.Generation, names: names}
	orderKey, orderURL, err := w.order(ctx, lease, t, acct, accountURL)
	if err != nil {
		return err
	}
	o, err := w.ca.Order(ctx, acct, accountURL, orderURL)
	if err != nil {
		w.dropOrder(ctx, lease, DomainResource(d))
		return err
	}
	if o.Status == acme.StatusPending {
		for _, authz := range o.AuthzURLs {
			if err := w.authorize(ctx, lease, d, acct, accountURL, authz); err != nil {
				return err
			}
		}
	}
	if o, err = w.waitOrder(ctx, acct, accountURL, orderURL); err != nil {
		return err
	}
	if o.Status != acme.StatusReady {
		// Invalid, or finalized before a crash: start over with a new order.
		w.dropOrder(ctx, lease, DomainResource(d))
		return fmt.Errorf("certificates: order is %s", o.Status)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, orderKey)
	if err != nil {
		return err
	}
	der, err := w.ca.Finalize(ctx, acct, accountURL, o.FinalizeURL, csr)
	if err != nil {
		return err
	}
	chainPEM, keyPEM, err := encodePair(der, orderKey)
	if err != nil {
		return err
	}
	if err := ValidateCertificate(chainPEM, keyPEM, names, w.m.clock(), w.cfg.Roots); err != nil {
		return errInvalidIssue{err}
	}
	return w.publish(ctx, lease, d, chainPEM, keyPEM)
}

type errInvalidIssue struct{ error }

// fenced runs fn in a transaction after checking the lease, so a worker that
// lost its lease can neither publish nor delete a successor's records.
func (w *Worker) fenced(ctx context.Context, lease store.TLSLease, fn func(tx store.Store) error) error {
	err := w.m.st.WithTx(ctx, func(tx store.Store) error {
		if err := tx.TLSAssets().CheckLease(ctx, lease); err != nil {
			return errStale
		}
		return fn(tx)
	})
	if errors.Is(err, store.ErrConflict) {
		return errStale
	}
	return err
}

func (w *Worker) publish(ctx context.Context, lease store.TLSLease, d *store.CustomDomain, chainPEM, keyPEM []byte) error {
	leafBlock, _ := pem.Decode(chainPEM)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return err
	}
	certKey := "cert/" + d.TenantID + "/" + d.ID
	sealed, err := w.m.Seal(store.TLSAssetCertificate, certKey, d.TenantID, d.ID, d.Generation, keyPEM)
	if err != nil {
		return err
	}
	resource := DomainResource(d)
	return w.fenced(ctx, lease, func(tx store.Store) error {
		cur, err := tx.CustomDomains().Get(ctx, d.TenantID, d.ID)
		if errors.Is(err, store.ErrNotFound) {
			return errStale
		}
		if err != nil {
			return err
		}
		if cur.Generation != d.Generation {
			return errStale
		}
		row := &store.TLSAsset{Key: certKey, Kind: store.TLSAssetCertificate, TenantID: d.TenantID, DomainID: d.ID, Generation: d.Generation, Ciphertext: sealed,
			PublicData: store.TLSPublicData{Version: PublicDataVersion, CertificateChainPEM: chainPEM, SANs: leaf.DNSNames, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
		var rev int64
		if old, err := tx.TLSAssets().Get(ctx, certKey); err == nil {
			rev = old.Revision
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.TLSAssets().Put(ctx, row, rev); err != nil {
			return err
		}
		if err := customdomain.ActivateManaged(ctx, tx, cur, certKey, w.m.clock(), RenewalTime(resource, leaf.NotBefore, leaf.NotAfter)); err != nil {
			return err
		}
		return deleteIfPresent(ctx, tx, "order/"+resource)
	})
}

func deleteIfPresent(ctx context.Context, tx store.Store, key string) error {
	row, err := tx.TLSAssets().Get(ctx, key)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return tx.TLSAssets().Delete(ctx, key, row.Revision)
}

func (w *Worker) dropOrder(ctx context.Context, lease store.TLSLease, resource string) {
	_ = w.fenced(context.WithoutCancel(ctx), lease, func(tx store.Store) error { return deleteIfPresent(ctx, tx, "order/"+resource) })
}

// fail records a safe failure message and the next attempt. A renewal
// failure keeps a domain ready while its certificate is valid.
func (w *Worker) fail(ctx context.Context, lease store.TLSLease, d *store.CustomDomain, cause error) {
	_ = w.fenced(ctx, lease, func(tx store.Store) error {
		cur, err := tx.CustomDomains().Get(ctx, d.TenantID, d.ID)
		if err != nil || cur.Generation != d.Generation {
			return errStale
		}
		now := w.m.clock()
		cur.AttemptCount++
		cur.LastFailure, cur.UpdatedAt = safeMessage(cause), now
		next := now.Add(backoff(cur.AttemptCount, cause))
		cur.NextAttemptAt = &next
		switch cur.Lifecycle {
		case customdomain.LifecycleActive, customdomain.LifecycleRenewalError:
			cur.Lifecycle = customdomain.LifecycleRenewalError
			if !w.certificateValid(ctx, tx, cur, now) {
				cur.Status = customdomain.StatusFailed
			}
		case customdomain.LifecycleIssuing:
			if cur.AttemptCount >= initialFailed {
				cur.Status = customdomain.StatusFailed
			}
		}
		return tx.CustomDomains().Update(ctx, cur, cur.Revision)
	})
}

func (w *Worker) certificateValid(ctx context.Context, tx store.Store, d *store.CustomDomain, now time.Time) bool {
	row, err := tx.TLSAssets().Get(ctx, d.ActiveCertificateKey)
	return err == nil && now.Before(row.PublicData.NotAfter)
}

// backoff doubles from one minute to six hours; a CA Retry-After is honored
// within the same cap.
func backoff(attempt int, cause error) time.Duration {
	d := time.Minute << min(attempt-1, 10)
	if ra, ok := acme.RateLimit(cause); ok && ra > d {
		d = ra
	}
	return min(d, maxBackoff)
}

// safeMessage never includes CA response bodies or internal errors.
func safeMessage(err error) string {
	var acmeErr *acme.Error
	var invalid errInvalidIssue
	switch {
	case errors.Is(err, customdomain.ErrProofMissing), errors.Is(err, customdomain.ErrProofUncertain):
		return "the domain's ownership proof could not be confirmed"
	case errors.As(err, &invalid):
		return "the issued certificate failed validation"
	case func() bool { _, ok := acme.RateLimit(err); return ok }():
		return "the certificate authority rate limited issuance"
	case errors.As(err, &acmeErr):
		return "the certificate authority rejected the request"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "certificate work was interrupted"
	}
	return "certificate issuance failed"
}

func (w *Worker) accountKey() string {
	sum := sha256.Sum256([]byte(w.m.cfg.DirectoryURL))
	return "account/" + hex.EncodeToString(sum[:8])
}

// account loads or creates the deployment's account for this directory. The
// key is saved before registering. A key that cannot be opened is an error:
// it is never replaced automatically.
func (w *Worker) account(ctx context.Context) (crypto.Signer, string, error) {
	key := w.accountKey()
	for range 3 {
		row, err := w.m.st.TLSAssets().Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			_, sealed, err := w.newKey(store.TLSAssetAccount, key, "", "", 0)
			if err != nil {
				return nil, "", err
			}
			row = &store.TLSAsset{Key: key, Kind: store.TLSAssetAccount, Ciphertext: sealed,
				PublicData: store.TLSPublicData{Version: PublicDataVersion, DirectoryURL: w.m.cfg.DirectoryURL}}
			if err := w.m.st.TLSAssets().Put(ctx, row, 0); errors.Is(err, store.ErrConflict) {
				continue
			} else if err != nil {
				return nil, "", err
			}
			continue
		}
		if err != nil {
			return nil, "", err
		}
		signer, err := w.openKey(row)
		if err != nil {
			return nil, "", fmt.Errorf("certificates: ACME account key cannot be opened; it is not replaced: %w", err)
		}
		if row.PublicData.AccountURL != "" {
			return signer, row.PublicData.AccountURL, nil
		}
		url, err := w.ca.Register(ctx, signer, w.cfg.Email)
		if err != nil {
			return nil, "", err
		}
		row.PublicData.AccountURL = url
		if err := w.m.st.TLSAssets().Put(ctx, row, row.Revision); err != nil && !errors.Is(err, store.ErrConflict) {
			return nil, "", err
		}
		return signer, url, nil
	}
	return nil, "", errors.New("certificates: ACME account changed concurrently")
}

// target is what an order certifies: a domain generation or the hosted
// wildcard (no tenant/domain owner).
type target struct {
	resource, tenantID, domainID string
	gen                          int64
	names                        []string
}

// order loads the saved order for this target or saves a new one (key,
// SANs, directory, account) before asking the CA, then saves its URL.
func (w *Worker) order(ctx context.Context, lease store.TLSLease, t target, acct crypto.Signer, accountURL string) (crypto.Signer, string, error) {
	key := "order/" + t.resource
	names := t.names
	row, err := w.m.st.TLSAssets().Get(ctx, key)
	switch {
	case errors.Is(err, store.ErrNotFound):
		_, sealed, err := w.newKey(store.TLSAssetOrder, key, t.tenantID, t.domainID, t.gen)
		if err != nil {
			return nil, "", err
		}
		row = &store.TLSAsset{Key: key, Kind: store.TLSAssetOrder, TenantID: t.tenantID, DomainID: t.domainID, Generation: t.gen, Ciphertext: sealed,
			ExpiresAt:  w.m.clock().Add(recordTTL),
			PublicData: store.TLSPublicData{Version: PublicDataVersion, DirectoryURL: w.m.cfg.DirectoryURL, AccountURL: accountURL, Status: "new", SANs: names}}
		if err := w.fenced(ctx, lease, func(tx store.Store) error { return tx.TLSAssets().Put(ctx, row, 0) }); err != nil {
			return nil, "", err
		}
	case err != nil:
		return nil, "", err
	}
	signer, err := w.openKey(row)
	if err != nil {
		return nil, "", err
	}
	if row.PublicData.OrderURL != "" && row.PublicData.AccountURL == accountURL {
		return signer, row.PublicData.OrderURL, nil
	}
	o, err := w.ca.NewOrder(ctx, acct, accountURL, names)
	if err != nil {
		return nil, "", err
	}
	row.PublicData.OrderURL, row.PublicData.AccountURL, row.PublicData.Status = o.URI, accountURL, "ordered"
	err = w.fenced(ctx, lease, func(tx store.Store) error { return tx.TLSAssets().Put(ctx, row, row.Revision) })
	return signer, o.URI, err
}

func (w *Worker) newKey(kind, key, tenantID, domainID string, gen int64) (crypto.Signer, []byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	sealed, err := w.m.Seal(kind, key, tenantID, domainID, gen, der)
	return k, sealed, err
}

func (w *Worker) openKey(row *store.TLSAsset) (crypto.Signer, error) {
	der, err := w.m.Open(row.Kind, row.Key, row.TenantID, row.DomainID, row.Generation, row.Ciphertext)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("certificates: stored key is not a signer")
	}
	return signer, nil
}

// authorize publishes the configured challenge for one authorization through
// a fenced write, asks the CA to validate it, waits, then removes it.
func (w *Worker) authorize(ctx context.Context, lease store.TLSLease, d *store.CustomDomain, acct crypto.Signer, accountURL, url string) error {
	a, err := w.ca.Authorization(ctx, acct, accountURL, url)
	if err != nil {
		return err
	}
	switch a.Status {
	case acme.StatusValid:
		return nil
	case acme.StatusPending:
	default:
		return fmt.Errorf("certificates: authorization is %s", a.Status)
	}
	var chal *acme.Challenge
	for _, c := range a.Challenges {
		if c.Type == w.cfg.Challenge {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("certificates: the CA offered no %s challenge", w.cfg.Challenge)
	}
	row, err := w.challengeRecord(acct, d, chal, a.Identifier.Value)
	if err != nil {
		return err
	}
	if err := w.fenced(ctx, lease, func(tx store.Store) error {
		if err := deleteIfPresent(ctx, tx, row.Key); err != nil {
			return err
		}
		return tx.TLSAssets().Put(ctx, row, 0)
	}); err != nil {
		return err
	}
	defer func() {
		_ = w.fenced(context.WithoutCancel(ctx), lease, func(tx store.Store) error { return deleteIfPresent(ctx, tx, row.Key) })
	}()
	if err := w.ca.Accept(ctx, acct, accountURL, chal); err != nil {
		return err
	}
	return w.waitAuthorization(ctx, acct, accountURL, url)
}

func (w *Worker) waitOrder(ctx context.Context, acct crypto.Signer, accountURL, url string) (*acme.Order, error) {
	for range pollAttempts {
		o, err := w.ca.Order(ctx, acct, accountURL, url)
		if err != nil {
			return nil, err
		}
		if o.Status != acme.StatusPending && o.Status != acme.StatusProcessing {
			return o, nil
		}
		if err := sleep(ctx, pollInterval); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("certificates: order did not become ready")
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
