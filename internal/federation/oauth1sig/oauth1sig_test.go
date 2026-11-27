package oauth1sig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

// TestOAuth1Signatures (Review Focus 2) reproduces the HMAC-SHA1 signatures
// of RFC 5849 §1.2: temporary credentials, token credentials and a resource
// request.
func TestOAuth1Signatures(t *testing.T) {
	for _, c := range []struct {
		name, method, url string
		creds             Credentials
		form              url.Values
		oauth             map[string]string
		want              string
	}{
		{"initiate", "POST", "https://photos.example.net/initiate", Credentials{ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44"}, nil,
			map[string]string{"oauth_timestamp": "137131200", "oauth_nonce": "wIjqoS", "oauth_callback": "http://printer.example.com/ready"}, "74KNZJeDHnMBp0EMJ9ZHt/XKycU="},
		{"token", "POST", "https://photos.example.net/token", Credentials{ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44", Token: "hh5s93j4hdidpola", TokenSecret: "hdhd0244k9j7ao03"}, nil,
			map[string]string{"oauth_timestamp": "137131201", "oauth_nonce": "walatlh", "oauth_verifier": "hfdp7dh39dks9884"}, "gKgrFCywp7rO0OXSjdot/IHF7IU="},
		{"resource", "GET", "http://photos.example.net/photos?file=vacation.jpg&size=original", Credentials{ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44", Token: "nnch734d00sl2jdk", TokenSecret: "pfkkdhi9sl3r4s00"}, nil,
			map[string]string{"oauth_timestamp": "137131202", "oauth_nonce": "chapoH"}, "MdpQcU8iPSUjWoN/UDMsK2sui9I="},
	} {
		t.Run(c.name, func(t *testing.T) {
			params, err := Params(c.creds, c.oauth)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Sign(c.creds, c.method, c.url, c.form, params)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("signature %s, want %s", got, c.want)
			}
		})
	}
}

// TestBaseString is RFC 5849 §3.4.1.1: duplicate keys, encoded query values,
// an empty body parameter and the oauth_* parameters.
func TestBaseString(t *testing.T) {
	form := url.Values{"c2": {""}, "a3": {"2 q"}}
	params := map[string]string{"oauth_consumer_key": "9djdj82h48djs9d2", "oauth_token": "kkk9d7dh3k39sjv7",
		"oauth_signature_method": "HMAC-SHA1", "oauth_timestamp": "137131201", "oauth_nonce": "7d8f3e4a"}
	got, err := BaseString("POST", "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b", form, params)
	if err != nil {
		t.Fatal(err)
	}
	const want = "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7"
	if got != want {
		t.Fatalf("base string\n%s\nwant\n%s", got, want)
	}
	if got, _ := BaseString("GET", "HTTPS://Example.COM:443/r%20x?", nil, nil); got != "GET&https%3A%2F%2Fexample.com%2Fr%2520x&" {
		t.Fatalf("normalized base URI %s", got)
	}
	if got, _ := BaseString("GET", "http://example.com:8080/", nil, nil); !strings.HasPrefix(got, "GET&http%3A%2F%2Fexample.com%3A8080%2F&") {
		t.Fatalf("non-default port %s", got)
	}
}

func TestRSASHA1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	creds := Credentials{ConsumerKey: "ck", RSAKey: key, Token: "tok"}
	params, _ := Params(creds, map[string]string{"oauth_timestamp": "1", "oauth_nonce": "n"})
	if params["oauth_signature_method"] != RSASHA1 {
		t.Fatalf("method %s", params["oauth_signature_method"])
	}
	sig, err := Sign(creds, "GET", "https://api.example/me?x=1", nil, params)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := BaseString("GET", "https://api.example/me?x=1", nil, params)
	raw, _ := base64.StdEncoding.DecodeString(sig)
	sum := sha1.Sum([]byte(base))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA1, sum[:], raw); err != nil {
		t.Fatalf("RSA-SHA1 signature does not verify: %v", err)
	}
}

func TestHeader(t *testing.T) {
	creds := Credentials{ConsumerKey: "dpf43f3p2l4k3l03", ConsumerSecret: "kd94hf93k423kf44"}
	h, err := Header(creds, "POST", "https://photos.example.net/initiate", nil, map[string]string{"oauth_callback": "http://printer.example.com/ready"}, "wIjqoS", "137131200")
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`OAuth `, `oauth_consumer_key="dpf43f3p2l4k3l03"`, `oauth_signature_method="HMAC-SHA1"`, `oauth_version="1.0"`,
		`oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready"`, `oauth_nonce="wIjqoS"`, `oauth_timestamp="137131200"`} {
		if !strings.Contains(h, part) {
			t.Fatalf("header %s lacks %s", h, part)
		}
	}
	if strings.Contains(h, "kd94hf93k423kf44") {
		t.Fatal("header carries the consumer secret")
	}
	// Reserved or invalid extra parameters are refused.
	for _, extra := range []map[string]string{{"oauth_signature": "x"}, {"oauth_consumer_key": "other"}, {"not_oauth": "x"}} {
		if _, err := Header(creds, "GET", "https://x.example/", nil, extra, "n", "1"); err == nil {
			t.Fatalf("extra %v accepted", extra)
		}
	}
	if _, err := Header(Credentials{ConsumerKey: "k"}, "GET", "https://x.example/", nil, nil, "n", "1"); err == nil {
		t.Fatal("no secret or key accepted")
	}
}
