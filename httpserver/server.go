// Package httpserver hosts the multi-tenant streamable-HTTP MCP endpoint
// behind mcp.{domain}. It is a pure resource server: OAuth authorization
// lives in the api (same host, /oauth/* — Traefik splits the paths); this
// process only verifies access tokens and serves MCP.
//
// Stateless streamable HTTP on purpose: Traefik load-balances across the
// region's be-app nodes, so no session affinity can be assumed.
package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"alertkick-mcp/client"
	"alertkick-mcp/config"
	"alertkick-mcp/tools"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type ctxKey string

const claimsKey ctxKey = "akmcp_claims"

// Server wires the streamable handler, metadata and health endpoints.
type Server struct {
	cfg     *config.Config
	version string
}

func New(cfg *config.Config, version string) *Server {
	return &Server{cfg: cfg, version: version}
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	streamable := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		claims, ok := r.Context().Value(claimsKey).(*AccessClaims)
		if !ok || claims == nil {
			// requireAuth guarantees claims; nil tells the SDK to refuse.
			return nil
		}
		apiClient := client.NewTenantClient(s.cfg, s.version, claims.Subdomain, bearerFromRequest(r), claims.HasScope("write"))
		server := mcp.NewServer(&mcp.Implementation{
			Name:    "alertkick-mcp",
			Version: s.version,
		}, nil)
		server.AddReceivingMiddleware(toolCallLogger(claims))
		tools.RegisterAll(server, apiClient)
		return server
	}, &mcp.StreamableHTTPOptions{
		Stateless: true,
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", s.requireAuth(streamable))
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/livez", s.health)
	mux.HandleFunc("/readyz", s.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"name":          "AlertKick MCP server",
			"mcp_endpoint":  s.cfg.Resource(),
			"documentation": s.cfg.DocsURL,
		})
	})

	httpServer := &http.Server{
		Addr:              s.cfg.HTTPAddr,
		Handler:           withCORS(withAccessLog(mux)),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("akmcp http mode listening on %s (resource %s)", s.cfg.HTTPAddr, s.cfg.Resource())
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// requireAuth enforces Bearer auth per the MCP authorization spec: a 401
// (never a tool error) with a WWW-Authenticate challenge pointing at the
// protected-resource metadata, so clients can discover the authorization
// server. Claude does not honor the challenge on a 200.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerFromRequest(r)
		if token == "" {
			s.unauthorized(w, "")
			return
		}
		claims, err := verifyAccessToken(token, s.cfg.OAuthSigningKey, s.cfg.PublicURL, s.cfg.Resource())
		if err != nil {
			s.unauthorized(w, "invalid_token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey, claims)))
	})
}

func (s *Server) unauthorized(w http.ResponseWriter, errCode string) {
	challenge := fmt.Sprintf(`Bearer resource_metadata=%q, scope="read write"`, s.cfg.PublicURL+"/.well-known/oauth-protected-resource")
	if errCode != "" {
		challenge = fmt.Sprintf(`Bearer error=%q, resource_metadata=%q, scope="read write"`, errCode, s.cfg.PublicURL+"/.well-known/oauth-protected-resource")
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": "A valid AlertKick MCP access token is required. Connect via OAuth.",
	})
}

// protectedResourceMetadata implements RFC 9728. The authorization server
// is the api, reachable on this same public host.
func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"resource":                 s.cfg.Resource(),
		"authorization_servers":    []string{s.cfg.PublicURL},
		"scopes_supported":         []string{"read", "write"},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "AlertKick",
		"resource_documentation":   s.cfg.DocsURL,
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "version": s.version})
}

func bearerFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && (h[:len(prefix)] == prefix || h[:len(prefix)] == "bearer ") {
		return h[len(prefix):]
	}
	return ""
}

// withCORS allows browser-based MCP clients (e.g. MCP Inspector).
// Credentials are bearer tokens, never cookies, so a permissive policy
// carries no CSRF surface.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
