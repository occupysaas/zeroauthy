package mgmt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strconv"
	"time"
)

// ExportLinkInfo is the HKDF info that derives the export link key from the
// master key (D-0044).
const ExportLinkInfo = "zeroauthy export link v1"

// ExportLinkLifetime is how long a download link of an export works, as
// Auth0's pre-signed URL does (J9).
const ExportLinkLifetime = 60 * time.Second

// ExportLink signs and checks the download links of completed exports
// (D-0044, zeroauthy's own; Auth0 hands out an object-storage URL). The link
// is https://<tenant host>/export/<job>/<tenant>.<format>.gz?expires=<unix>&sig=<mac>,
// where mac is the base64url HMAC-SHA256 of the tenant ID, the job ID and
// the expiry. Now is the clock; nil is time.Now.
type ExportLink struct {
	Key []byte
	Now func() time.Time
}

func (l ExportLink) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l ExportLink) mac(tenantID, jobID string, expires int64) []byte {
	m := hmac.New(sha256.New, l.Key)
	m.Write([]byte(tenantID + "\n" + jobID + "\n" + strconv.FormatInt(expires, 10)))
	return m.Sum(nil)
}

// Sign returns a link to the job's file that works for ExportLinkLifetime.
// host is the tenant host the request used; tenantName names the file.
func (l ExportLink) Sign(host, tenantName, tenantID, jobID, format string) string {
	expires := l.now().Add(ExportLinkLifetime).Unix()
	q := url.Values{
		"expires": {strconv.FormatInt(expires, 10)},
		"sig":     {base64.RawURLEncoding.EncodeToString(l.mac(tenantID, jobID, expires))},
	}
	return "https://" + host + "/export/" + jobID + "/" + tenantName + "." + format + ".gz?" + q.Encode()
}

// Check reports whether sig is the signature of the tenant's job and expires
// has not passed.
func (l ExportLink) Check(tenantID, jobID string, expires int64, sig string) bool {
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	// Compare first, so that the time does not depend on where they differ.
	ok := subtle.ConstantTimeCompare(got, l.mac(tenantID, jobID, expires)) == 1
	return ok && l.now().Unix() <= expires
}
