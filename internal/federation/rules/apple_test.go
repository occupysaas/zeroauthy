package rules

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

func applePEM(t *testing.T, key any) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func TestAppleRules(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	sec1, _ := x509.MarshalECPrivateKey(key)
	base := map[string]any{"client_id": "com.example.web", "team_id": "ABCDEFGHIJ", "kid": "0123456789", "app_secret": applePEM(t, key)}
	type ruleCase struct {
		name        string
		change      func(map[string]any)
		sealed, bad bool
		scopes      []string
	}
	tests := []ruleCase{
		{name: "defaults", scopes: []string{"name", "email"}},
		{name: "no scopes", change: func(o map[string]any) { o["name"] = false; o["email"] = false; o["scope"] = "" }, scopes: []string{}},
		{name: "explicit scopes", change: func(o map[string]any) { o["scope"] = "email name" }, scopes: []string{"name", "email"}},
		{name: "allowed freeform", change: func(o map[string]any) { o["freeform_scopes"] = []any{"email", "name"} }, scopes: []string{"name", "email"}},
		{name: "preserve omitted key", change: func(o map[string]any) { delete(o, "app_secret") }, sealed: true, scopes: []string{"name", "email"}},
	}
	for _, k := range []string{"client_id", "team_id", "kid", "app_secret"} {
		k := k
		tests = append(tests, ruleCase{name: "missing " + k, change: func(o map[string]any) { delete(o, k) }, bad: true})
	}
	for name, change := range map[string]func(map[string]any){
		"short team":    func(o map[string]any) { o["team_id"] = "abc" },
		"lowercase kid": func(o map[string]any) { o["kid"] = "abcdefghij" },
		"long client":   func(o map[string]any) { o["client_id"] = strings.Repeat("x", 256) },
		"null key":      func(o map[string]any) { o["app_secret"] = nil },
		"empty key":     func(o map[string]any) { o["app_secret"] = "" },
		"bad PEM":       func(o map[string]any) { o["app_secret"] = "PRIVATE-KEY-SENTINEL" },
		"RSA":           func(o map[string]any) { o["app_secret"] = applePEM(t, rsaKey) },
		"P384":          func(o map[string]any) { o["app_secret"] = applePEM(t, p384) },
		"PKCS1":         func(o map[string]any) { o["app_secret"] = pkcs1 },
		"SEC1": func(o map[string]any) {
			o["app_secret"] = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
		},
		"trailing key":      func(o map[string]any) { o["app_secret"] = base["app_secret"].(string) + "extra" },
		"bad flag":          func(o map[string]any) { o["name"] = "true" },
		"array scope":       func(o map[string]any) { o["scope"] = []any{"name", "email"} },
		"null scope":        func(o map[string]any) { o["scope"] = nil },
		"unknown scope":     func(o map[string]any) { o["scope"] = "openid" },
		"scope mismatch":    func(o map[string]any) { o["email"] = false; o["scope"] = "name email" },
		"freeform openid":   func(o map[string]any) { o["freeform_scopes"] = []any{"openid"} },
		"freeform type":     func(o map[string]any) { o["freeform_scopes"] = "name" },
		"freeform mismatch": func(o map[string]any) { o["name"] = false; o["freeform_scopes"] = []any{"name"} },
	} {
		tests = append(tests, ruleCase{name: name, change: change, bad: true, sealed: true})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := maps.Clone(base)
			if tt.change != nil {
				tt.change(o)
			}
			settings, errs := Parse(Input{Strategy: "apple", Name: "apple", Options: o, HasSealedSecret: tt.sealed})
			if (len(errs) > 0) != tt.bad {
				t.Fatalf("errors=%v want bad=%v", errs, tt.bad)
			}
			if strings.Contains(fmt.Sprint(errs), "PRIVATE-KEY-SENTINEL") || strings.Contains(fmt.Sprint(errs), "-----BEGIN") {
				t.Fatal("validation leaks signing material")
			}
			if !tt.bad && !slices.Equal(settings.Scopes, tt.scopes) {
				t.Fatalf("scopes=%v want=%v", settings.Scopes, tt.scopes)
			}
			if !tt.bad && (!IsFederated("apple") || !IsSocial("apple")) {
				t.Fatal("Apple must use federation and social identity handling")
			}
		})
	}
}
