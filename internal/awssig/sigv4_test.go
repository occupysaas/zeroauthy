package awssig

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSESSigV4ReferenceVector(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	const stringToSign = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
	date := signHMAC([]byte("AWS4"+secret), "20150830")
	region := signHMAC(date, "us-east-1")
	service := signHMAC(region, "iam")
	key := signHMAC(service, "aws4_request")
	signature := hex.EncodeToString(signHMAC(key, stringToSign))
	if signature != "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" {
		t.Fatalf("SigV4 reference signature=%s", signature)
	}
}

func TestSignSetsHeaders(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails", nil)
	req.Header.Set("Content-Type", "application/json")
	Sign(req, []byte(`{}`), "eu-west-1", "ses", "AKID", "secret", time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC))
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKID/20261103/eu-west-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=") {
		t.Fatalf("authorization=%s", auth)
	}
	if req.Header.Get("X-Amz-Date") != "20261103T010203Z" || len(req.Header.Get("X-Amz-Content-Sha256")) != 64 {
		t.Fatalf("headers=%v", req.Header)
	}
}

// TestSignSNSKnownSignature checks a form POST with the headers SNS uses
// against a signature computed independently (Python hmac/hashlib over the
// SigV4 algorithm), not by calling Sign.
func TestSignSNSKnownSignature(t *testing.T) {
	body := []byte("Action=Publish&Message=hi&PhoneNumber=%2B14155550100&Version=2010-03-31")
	req, _ := http.NewRequest(http.MethodPost, "https://sns.eu-west-1.amazonaws.com/", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	Sign(req, body, "eu-west-1", "sns", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", time.Date(2026, 11, 3, 1, 2, 3, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261103/eu-west-1/sns/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=a5a00e639b03e1e67448bc787d131528f1517977925b3c69e6701996aa8fd40c"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("authorization=%s", got)
	}
	if req.Header.Get("X-Amz-Content-Sha256") != "c3a6aeeda9dac1136ab3d947eae288a2551873df07502372658ed31adb2a99fa" {
		t.Fatalf("payload hash=%s", req.Header.Get("X-Amz-Content-Sha256"))
	}
}
