// Package awssig signs AWS requests with Signature Version 4. It is shared by
// the SES email transport and the SNS phone sender.
package awssig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Sign sets X-Amz-Date, X-Amz-Content-Sha256 and Authorization on req. body is
// the exact request payload (nil for none). Signed headers are content-type
// (when set), host, x-amz-content-sha256 and x-amz-date.
func Sign(req *http.Request, body []byte, region, service, keyID, secret string, now time.Time) {
	date := now.UTC()
	amz := date.Format("20060102T150405Z")
	day := date.Format("20060102")
	sum := sha256.Sum256(body)
	payloadHash := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Date", amz)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	signed := "host;x-amz-content-sha256;x-amz-date"
	headers := "host:" + host + "\nx-amz-content-sha256:" + payloadHash + "\nx-amz-date:" + amz + "\n"
	if ct := req.Header.Get("Content-Type"); ct != "" {
		signed = "content-type;" + signed
		headers = "content-type:" + strings.TrimSpace(ct) + "\n" + headers
	}
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := strings.ReplaceAll(url.Values(req.URL.Query()).Encode(), "+", "%20")
	canonical := req.Method + "\n" + path + "\n" + query + "\n" + headers + "\n" + signed + "\n" + payloadHash
	ch := sha256.Sum256([]byte(canonical))
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amz + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	k := signHMAC([]byte("AWS4"+secret), day)
	k = signHMAC(k, region)
	k = signHMAC(k, service)
	k = signHMAC(k, "aws4_request")
	sig := hex.EncodeToString(signHMAC(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+", SignedHeaders="+signed+", Signature="+sig)
}

func signHMAC(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}
