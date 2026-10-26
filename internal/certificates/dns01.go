package certificates

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/zeroauthy/zeroauthy/internal/customdomain"
	"github.com/zeroauthy/zeroauthy/internal/store"
)

// DNSRecord is a provider TXT record. Created is true only when this
// deployment created it; only such records are ever deleted.
type DNSRecord struct {
	ID, Zone, Name, Value string
	Created               bool
}

// DNSProvider manages exact TXT records. Present never replaces other
// values at the name; CleanUp deletes only a created record by ID; Find
// inspects exact name/value matches for crash recovery.
type DNSProvider interface {
	Present(ctx context.Context, zone, name, value string) (DNSRecord, error)
	CleanUp(ctx context.Context, record DNSRecord) error
	Find(ctx context.Context, zone, name, value string) (DNSRecord, int, error)
}

// ChallengeResolver checks delegation and propagation through the
// deployment resolver.
type ChallengeResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
	LookupNS(ctx context.Context, name string) ([]string, error)
}

// HostedConfig enables the hosted wildcard: base_domain and *.base_domain
// through DNS-01 in Zone.
type HostedConfig struct {
	BaseDomain, Zone   string
	Provider           DNSProvider
	Resolver           ChallengeResolver
	PropagationTimeout time.Duration // default 10m
	PollMin, PollMax   time.Duration // default 5s and 30s
}

// HostedResource is the lease and order key of the hosted wildcard.
func HostedResource(deploymentID, baseDomain string) string {
	return "hosted/" + deploymentID + "/" + strings.ToLower(baseDomain)
}

var errDelegated = errors.New("certificates: the DNS-01 challenge name is delegated (CNAME or NS); delegation is unsupported")

func (w *Worker) reconcileHosted(ctx context.Context, key string) error {
	h := w.cfg.Hosted
	if h == nil || key != HostedResource(w.m.cfg.DeploymentID, h.BaseDomain) {
		return fmt.Errorf("certificates: unknown resource %q", key)
	}
	return w.withLease(ctx, key, func(ctx context.Context, lease store.TLSLease) error {
		if !w.hostedDue(ctx, key) {
			return nil
		}
		err := w.issueHosted(ctx, lease, key)
		w.mu.Lock()
		defer w.mu.Unlock()
		if err != nil && !errors.Is(err, errStale) {
			w.hostedFailures++
			w.hostedNext = w.m.clock().Add(backoff(w.hostedFailures, err))
		} else if err == nil {
			w.hostedFailures, w.hostedNext = 0, time.Time{}
		}
		return err
	})
}

// hostedDue: no certificate yet or renewal time reached, and not backing off.
func (w *Worker) hostedDue(ctx context.Context, key string) bool {
	now := w.m.clock()
	w.mu.Lock()
	next := w.hostedNext
	w.mu.Unlock()
	if now.Before(next) {
		return false
	}
	row, err := w.m.st.TLSAssets().Get(ctx, HostedWildcardKey)
	if errors.Is(err, store.ErrNotFound) {
		return true
	}
	return err == nil && !now.Before(RenewalTime(key, row.PublicData.NotBefore, row.PublicData.NotAfter))
}

func (w *Worker) issueHosted(ctx context.Context, lease store.TLSLease, key string) error {
	h := w.cfg.Hosted
	base := strings.ToLower(h.BaseDomain)
	if err := w.checkDelegation(ctx, base); err != nil {
		return err
	}
	acct, accountURL, err := w.account(ctx)
	if err != nil {
		return err
	}
	t := target{resource: key, names: []string{base, "*." + base}}
	orderKey, orderURL, err := w.order(ctx, lease, t, acct, accountURL)
	if err != nil {
		return err
	}
	o, err := w.ca.Order(ctx, acct, accountURL, orderURL)
	if err != nil {
		w.dropOrder(ctx, lease, key)
		return err
	}
	if o.Status == acme.StatusPending {
		if err := w.authorizeDNS(ctx, lease, t, acct, accountURL, o.AuthzURLs); err != nil {
			return err
		}
	}
	if o, err = w.waitOrder(ctx, acct, accountURL, orderURL); err != nil {
		return err
	}
	if o.Status != acme.StatusReady {
		w.dropOrder(ctx, lease, key)
		return fmt.Errorf("certificates: order is %s", o.Status)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: t.names}, orderKey)
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
	if err := ValidateCertificate(chainPEM, keyPEM, t.names, w.m.clock(), w.cfg.Roots); err != nil {
		return errInvalidIssue{err}
	}
	leafBlock, _ := pem.Decode(chainPEM)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return err
	}
	sealed, err := w.m.Seal(store.TLSAssetCertificate, HostedWildcardKey, "", "", 0, keyPEM)
	if err != nil {
		return err
	}
	return w.fenced(ctx, lease, func(tx store.Store) error {
		row := &store.TLSAsset{Key: HostedWildcardKey, Kind: store.TLSAssetCertificate, Ciphertext: sealed,
			PublicData: store.TLSPublicData{Version: PublicDataVersion, CertificateChainPEM: chainPEM, SANs: leaf.DNSNames, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}}
		var rev int64
		if old, err := tx.TLSAssets().Get(ctx, HostedWildcardKey); err == nil {
			rev = old.Revision
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := tx.TLSAssets().Put(ctx, row, rev); err != nil {
			return err
		}
		return deleteIfPresent(ctx, tx, "order/"+key)
	})
}

func encodePair(der [][]byte, key crypto.Signer) (chainPEM, keyPEM []byte, err error) {
	for _, c := range der {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	k, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return chainPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k}), nil
}

// checkDelegation refuses CNAME or NS delegation of the challenge name, or of
// base_domain below the provider zone: this provider only writes its zone.
func (w *Worker) checkDelegation(ctx context.Context, base string) error {
	h := w.cfg.Hosted
	name := "_acme-challenge." + base
	if _, err := h.Resolver.LookupCNAME(ctx, name); err == nil {
		return errDelegated
	} else if !errors.Is(err, customdomain.ErrDNSNotFound) {
		return err
	}
	cuts := []string{name}
	if base != strings.ToLower(h.Zone) {
		cuts = append(cuts, base)
	}
	for _, n := range cuts {
		if ns, err := h.Resolver.LookupNS(ctx, n); err == nil && len(ns) > 0 {
			return errDelegated
		} else if err != nil && !errors.Is(err, customdomain.ErrDNSNotFound) {
			return err
		}
	}
	return nil
}

func intentKey(resource, value string) string {
	sum := sha256.Sum256([]byte(value))
	return "dns-intent/" + resource + "/" + hex.EncodeToString(sum[:12])
}

// authorizeDNS presents every DNS-01 value first (apex and wildcard values
// coexist at one name), waits for propagation, asks the CA to validate, and
// always removes the records it created.
func (w *Worker) authorizeDNS(ctx context.Context, lease store.TLSLease, t target, acct crypto.Signer, accountURL string, authzURLs []string) error {
	type pending struct {
		url  string
		chal *acme.Challenge
		name string
		val  string
	}
	var todo []pending
	var records []DNSRecord
	var intents []string
	defer func() {
		cctx := context.WithoutCancel(ctx)
		for i, rec := range records {
			if rec.Created {
				if err := w.cfg.Hosted.Provider.CleanUp(cctx, rec); err != nil {
					continue // keep the intent; expiry cleanup retries
				}
			}
			_ = w.fenced(cctx, lease, func(tx store.Store) error { return deleteIfPresent(cctx, tx, intents[i]) })
		}
	}()
	for _, url := range authzURLs {
		a, err := w.ca.Authorization(ctx, acct, accountURL, url)
		if err != nil {
			return err
		}
		if a.Status == acme.StatusValid {
			continue
		}
		if a.Status != acme.StatusPending {
			return fmt.Errorf("certificates: authorization is %s", a.Status)
		}
		i := slices.IndexFunc(a.Challenges, func(c *acme.Challenge) bool { return c.Type == "dns-01" })
		if i < 0 {
			return errors.New("certificates: the CA offered no dns-01 challenge")
		}
		val, err := w.ca.DNS01(acct, a.Challenges[i].Token)
		if err != nil {
			return err
		}
		p := pending{url: url, chal: a.Challenges[i], name: "_acme-challenge." + a.Identifier.Value, val: val}
		rec, ikey, err := w.presentOwned(ctx, lease, t, p.name, p.val)
		if err != nil {
			// The intent stays: a lost reply is recovered by exact inspection.
			return err
		}
		records, intents = append(records, rec), append(intents, ikey)
		todo = append(todo, p)
	}
	for _, p := range todo {
		if err := w.propagated(ctx, p.name, p.val); err != nil {
			return err
		}
	}
	for _, p := range todo {
		if err := w.ca.Accept(ctx, acct, accountURL, p.chal); err != nil {
			return err
		}
	}
	for _, p := range todo {
		if err := w.waitAuthorization(ctx, acct, accountURL, p.url); err != nil {
			return err
		}
	}
	return nil
}

// presentOwned records intent before the provider call and ownership after
// it. An intent left without a record ID (a lost reply) is recovered by exact
// inspection: one match is ours; several are ambiguous and never deleted.
func (w *Worker) presentOwned(ctx context.Context, lease store.TLSLease, t target, name, value string) (DNSRecord, string, error) {
	h := w.cfg.Hosted
	key := intentKey(t.resource, value)
	row, err := w.m.st.TLSAssets().Get(ctx, key)
	switch {
	case err == nil && row.PublicData.DNSRecordID != "":
		return DNSRecord{ID: row.PublicData.DNSRecordID, Zone: h.Zone, Name: name, Value: value, Created: row.PublicData.Status == "created"}, key, nil
	case err == nil:
		rec, n, err := h.Provider.Find(ctx, h.Zone, name, value)
		if err != nil {
			return DNSRecord{}, key, err
		}
		switch {
		case n == 1:
			rec.Created = true
			return rec, key, w.recordIntent(ctx, lease, row, rec)
		case n > 1:
			rec.Created = false
			return rec, key, w.recordIntent(ctx, lease, row, DNSRecord{ID: "ambiguous", Zone: h.Zone, Name: name, Value: value})
		}
	case errors.Is(err, store.ErrNotFound):
		row = &store.TLSAsset{Key: key, Kind: store.TLSAssetDNSIntent, ExpiresAt: w.m.clock().Add(recordTTL),
			PublicData: store.TLSPublicData{Version: PublicDataVersion, Identifier: t.resource, RecordName: name, RecordValue: value, Status: "creating"}}
		if err := w.fenced(ctx, lease, func(tx store.Store) error { return tx.TLSAssets().Put(ctx, row, 0) }); err != nil {
			return DNSRecord{}, "", err
		}
	default:
		return DNSRecord{}, "", err
	}
	rec, err := h.Provider.Present(ctx, h.Zone, name, value)
	if err != nil {
		return DNSRecord{}, key, err
	}
	return rec, key, w.recordIntent(ctx, lease, row, rec)
}

func (w *Worker) recordIntent(ctx context.Context, lease store.TLSLease, row *store.TLSAsset, rec DNSRecord) error {
	return w.fenced(ctx, lease, func(tx store.Store) error {
		cur, err := tx.TLSAssets().Get(ctx, row.Key)
		if err != nil {
			return err
		}
		cur.PublicData.DNSRecordID, cur.PublicData.Status = rec.ID, "existing"
		if rec.Created {
			cur.PublicData.Status = "created"
		}
		return tx.TLSAssets().Put(ctx, cur, cur.Revision)
	})
}

// propagated polls the deployment resolver until value is visible at name,
// backing off from PollMin to PollMax within PropagationTimeout.
func (w *Worker) propagated(ctx context.Context, name, value string) error {
	h := w.cfg.Hosted
	deadline, lo, hi := h.PropagationTimeout, h.PollMin, h.PollMax
	if deadline <= 0 {
		deadline = 10 * time.Minute
	}
	if lo <= 0 {
		lo = 5 * time.Second
	}
	if hi < lo {
		hi = max(lo, 30*time.Second)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for wait := lo; ; wait = min(wait*2, hi) {
		values, err := h.Resolver.LookupTXT(ctx, name)
		if err == nil && slices.Contains(values, value) {
			return nil
		}
		if err := sleep(ctx, wait); err != nil {
			return fmt.Errorf("certificates: the DNS-01 record did not propagate: %w", err)
		}
	}
}

func (w *Worker) waitAuthorization(ctx context.Context, acct crypto.Signer, accountURL, url string) error {
	for range pollAttempts {
		a, err := w.ca.Authorization(ctx, acct, accountURL, url)
		if err != nil {
			return err
		}
		switch a.Status {
		case acme.StatusValid:
			return nil
		case acme.StatusPending, acme.StatusProcessing:
		default:
			return fmt.Errorf("certificates: authorization is %s", a.Status)
		}
		if err := sleep(ctx, pollInterval); err != nil {
			return err
		}
	}
	return errors.New("certificates: authorization did not complete")
}
