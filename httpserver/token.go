package httpserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AccessClaims mirrors the api's sessions.MCPAccessClaims wire format.
type AccessClaims struct {
	TokenUse    string `json:"use"`
	Subdomain   string `json:"tenant"`
	AccountUUID string `json:"account"`
	Username    string `json:"username"`
	Scope       string `json:"scope"`
	GrantID     string `json:"gid"`
	ClientID    string `json:"cid"`
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
	Subject     string `json:"sub"`
	ExpiresAt   int64  `json:"exp"`
	IssuedAt    int64  `json:"iat"`
}

// HasScope reports whether the space-separated scope list contains want.
func (c *AccessClaims) HasScope(want string) bool {
	for _, s := range strings.Fields(c.Scope) {
		if s == want {
			return true
		}
	}
	return false
}

// verifyAccessToken validates an HS256 JWT minted by the api's OAuth
// server: signature, expiry, issuer, audience (RFC 8707 — the token must
// be bound to THIS server) and the use discriminator. Deliberately
// dependency-free: HS256 verification is an HMAC over two base64 segments.
//
// The api re-verifies everything (including grant revocation) on every
// forwarded request; this check exists so the MCP layer never processes a
// request, or leaks tool output, for a token that isn't ours.
func verifyAccessToken(tokenString, signingKey, issuer, audience string) (*AccessClaims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed token")
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed token header")
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil || header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported token algorithm")
	}

	mac := hmac.New(sha256.New, []byte(signingKey))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, fmt.Errorf("invalid token signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed token claims")
	}
	claims := &AccessClaims{}
	if err := json.Unmarshal(claimsJSON, claims); err != nil {
		return nil, fmt.Errorf("malformed token claims")
	}

	if claims.TokenUse != "mcp_access" {
		return nil, fmt.Errorf("not an MCP access token")
	}
	if claims.ExpiresAt == 0 || time.Now().Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}
	if claims.Issuer != issuer {
		return nil, fmt.Errorf("wrong token issuer")
	}
	if claims.Audience != audience {
		return nil, fmt.Errorf("token audience is not this server")
	}
	if claims.Subdomain == "" || claims.Subject == "" {
		return nil, fmt.Errorf("token missing tenant binding")
	}
	return claims, nil
}
