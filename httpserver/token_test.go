package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

const (
	testKey      = "test-signing-key"
	testIssuer   = "https://mcp.alertkick.test"
	testResource = "https://mcp.alertkick.test/mcp"
)

func mintTestToken(t *testing.T, key string, claims map[string]interface{}) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(header + "." + payload))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validClaims() map[string]interface{} {
	return map[string]interface{}{
		"use":     "mcp_access",
		"tenant":  "acme",
		"account": "acct-1",
		"scope":   "read write offline_access",
		"gid":     "mcg_x",
		"iss":     testIssuer,
		"aud":     testResource,
		"sub":     "user-1",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}
}

func TestVerifyAccessToken(t *testing.T) {
	tok := mintTestToken(t, testKey, validClaims())
	claims, err := verifyAccessToken(tok, testKey, testIssuer, testResource)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if claims.Subdomain != "acme" || claims.Subject != "user-1" {
		t.Fatalf("claims mismatch: %+v", claims)
	}
	if !claims.HasScope("write") || claims.HasScope("admin") {
		t.Fatal("scope parsing broken")
	}
}

func TestVerifyAccessTokenRejections(t *testing.T) {
	mutate := func(f func(m map[string]interface{})) string {
		c := validClaims()
		f(c)
		return mintTestToken(t, testKey, c)
	}
	cases := map[string]string{
		"wrong key":      mintTestToken(t, "other-key", validClaims()),
		"expired":        mutate(func(m map[string]interface{}) { m["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"no exp":         mutate(func(m map[string]interface{}) { delete(m, "exp") }),
		"wrong use":      mutate(func(m map[string]interface{}) { m["use"] = "session" }),
		"wrong issuer":   mutate(func(m map[string]interface{}) { m["iss"] = "https://evil.example" }),
		"wrong audience": mutate(func(m map[string]interface{}) { m["aud"] = "https://other.example/mcp" }),
		"no tenant":      mutate(func(m map[string]interface{}) { delete(m, "tenant") }),
		"garbage":        "not.a.jwt",
	}
	for name, tok := range cases {
		if _, err := verifyAccessToken(tok, testKey, testIssuer, testResource); err == nil {
			t.Errorf("%s: token accepted, want rejection", name)
		}
	}
}

// alg=none must never verify (classic JWT pitfall).
func TestVerifyAccessTokenAlgNone(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	body, _ := json.Marshal(validClaims())
	tok := header + "." + base64.RawURLEncoding.EncodeToString(body) + "."
	if _, err := verifyAccessToken(tok, testKey, testIssuer, testResource); err == nil {
		t.Fatal("alg=none token accepted")
	}
}
