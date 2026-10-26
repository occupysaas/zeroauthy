package customdomain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strconv"
	"time"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// Internal lifecycle states (design §5). Public status is projected from these.
const (
	LifecycleProofPending = "proof_pending" // awaiting DNS proof (or explicit self-managed verify)
	LifecycleIssuing      = "issuing"       // managed proof verified; certificate work queued
	LifecycleActive       = "active"
	LifecycleRenewalError = "renewal_error" // still serving its last valid certificate
	LifecycleSuspended    = "suspended"     // ownership lost beyond the grace period
	LifecycleFailed       = "failed"        // initial verification paused or provisioning failed

	StatusPending = "pending_verification"
	StatusReady   = "ready"
	StatusFailed  = "failed"

	ProofPending  = "pending"
	ProofVerified = "verified"
	ProofFailed   = "failed"

	TypeManaged     = "auth0_managed_certs"
	TypeSelfManaged = "self_managed_certs"
	SourceAPI       = "api"

	ProofRecordPrefix = "_zeroauthy-domain-verification."
	ProofValuePrefix  = "zeroauthy-domain-verification="
)

const (
	initialPause   = 72 * time.Hour // initial verification stops retrying
	lossGrace      = 24 * time.Hour // continuous proof loss before suspension
	recheckEvery   = 24 * time.Hour // self-managed ownership recheck
	maxJitterRatio = 0.10
)

var retryDelays = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}

// retryDelay is the nominal delay before the attempt-th try (1-based).
func retryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return retryDelays[min(attempt, len(retryDelays))-1]
}

// jitter spreads d by up to ±10% using random.
func jitter(d time.Duration, random io.Reader) (time.Duration, error) {
	var b [8]byte
	if _, err := io.ReadFull(random, b[:]); err != nil {
		return 0, err
	}
	f := float64(binary.BigEndian.Uint64(b[:])>>11) / float64(1<<53) // [0,1)
	return d + time.Duration((f*2-1)*maxJitterRatio*float64(d)), nil
}

// ProofValue binds the random proof token to the tenant, domain ID and
// generation, so a record published for another binding never matches.
func ProofValue(d *store.CustomDomain) string {
	m := hmac.New(sha256.New, d.ProofToken)
	m.Write([]byte(d.TenantID + "\x00" + d.ID + "\x00" + strconv.FormatInt(d.Generation, 10)))
	return ProofValuePrefix + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Usable reports whether a domain may serve requests or be chosen as an origin.
func Usable(d *store.CustomDomain) bool {
	return d != nil && d.Status == StatusReady && (d.Lifecycle == LifecycleActive || d.Lifecycle == LifecycleRenewalError)
}

// HashProxyKey is the only stored form of a self-managed proxy key.
func HashProxyKey(key string) []byte {
	sum := sha256.Sum256([]byte(key))
	return sum[:]
}
