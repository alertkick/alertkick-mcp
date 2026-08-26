package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"alertkick-mcp/config"
)

func testServer() *Server {
	return New(&config.Config{
		HTTPAddr:        ":0",
		PublicURL:       testIssuer,
		OAuthSigningKey: testKey,
		InternalAPIURL:  "http://api.invalid:9191",
		TenantDomain:    "alertkick.test",
		DocsURL:         "https://docs.alertkick.test",
	}, "test")
}

func TestUnauthenticatedMCPGets401WithChallenge(t *testing.T) {
	s := testServer()
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler reached without auth")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	www := rec.Header().Get("WWW-Authenticate")
	if !strings.Contains(www, `resource_metadata="`+testIssuer+`/.well-known/oauth-protected-resource"`) {
		t.Fatalf("WWW-Authenticate missing resource_metadata: %q", www)
	}
	if !strings.HasPrefix(www, "Bearer ") {
		t.Fatalf("WWW-Authenticate must be a Bearer challenge: %q", www)
	}
}

func TestAuthenticatedRequestReachesHandler(t *testing.T) {
	s := testServer()
	reached := false
	h := s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		claims, _ := r.Context().Value(claimsKey).(*AccessClaims)
		if claims == nil || claims.Subdomain != "acme" {
			t.Fatalf("claims not propagated: %+v", claims)
		}
	}))
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mintTestToken(t, testKey, validClaims()))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !reached {
		t.Fatal("valid token did not reach handler")
	}
}

func TestProtectedResourceMetadata(t *testing.T) {
	s := testServer()
	rec := httptest.NewRecorder()
	s.protectedResourceMetadata(rec, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	body := rec.Body.String()
	for _, want := range []string{`"resource":"` + testResource + `"`, `"authorization_servers":["` + testIssuer + `"]`, `"read"`, `"write"`} {
		if !strings.Contains(body, want) {
			t.Errorf("metadata missing %s in %s", want, body)
		}
	}
}

func TestAccessLogPassesStatusThrough(t *testing.T) {
	h := withAccessLog(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("x"))
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rr.Code)
	}
	if got := clientIP(req); got != "203.0.113.9" {
		t.Fatalf("clientIP = %q, want first XFF hop", got)
	}
}
