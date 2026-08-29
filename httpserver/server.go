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
	"strings"
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
	streamable := s.streamableHandler()

	mux := http.NewServeMux()
	mux.Handle("/mcp", s.requireAuth(streamable))
	// Pre-connection discovery, so deliberately unauthenticated. The path is
	// the one MCP reserves: <streamable-http-url>/server-card.
	mux.HandleFunc("/mcp/server-card", s.serverCard)
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

// serverCard serves this server's MCP Server Card (SEP-2127) at the reserved
// <streamable-http-url>/server-card location.
//
// Deliberately NOT under /.well-known: the spec calls that out as wrong for a
// single server's card, since .well-known is for site-wide metadata. The
// site-wide half is the AI Catalog at alertkick.com/.well-known/ai-catalog.json,
// which points here.
//
// Primitives (tools) are omitted on purpose - the spec excludes them because
// what a server exposes varies per authenticated user, and a static list would
// drift. Version comes from the running binary so the card cannot contradict
// the serverInfo a client sees after connecting.
// supportedProtocolVersions is what the Server Card advertises and what
// TestSupportedProtocolVersionsAreAccepted asserts the SDK actually accepts, so
// the card cannot claim a version the server would reject.
var supportedProtocolVersions = []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"}

func (s *Server) serverCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/mcp-server-card+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	// Browser-based clients fetch this before any credentialed call.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"$schema":     "https://static.modelcontextprotocol.io/schemas/v1/server-card.schema.json",
		"name":        "com.alertkick/alertkick-mcp",
		"title":       "AlertKick",
		"description": "Uptime, infrastructure and security monitoring. Create and manage HTTP, DNS, TCP, certificate-expiry, domain-expiry and mail-posture monitors, cron-job heartbeats, on-call rosters and escalation policies; read and acknowledge alerts, incidents and eBPF security events; raise and approve change windows. Scoped to a single workspace.",
		"version":     strings.TrimPrefix(s.version, "v"),
		"websiteUrl":  "https://alertkick.com",
		"repository": map[string]string{
			"url":    "https://github.com/alertkick/alertkick-mcp",
			"source": "github",
		},
		"icons": []map[string]string{
			{"src": "https://alertkick.com/logo.png", "mimeType": "image/png"},
		},
		"remotes": []map[string]interface{}{
			{
				"type":                      "streamable-http",
				"url":                       s.cfg.Resource(),
				"supportedProtocolVersions": supportedProtocolVersions,
			},
		},
		"_meta": map[string]interface{}{
			"com.alertkick": map[string]interface{}{
				"documentationUrl": s.cfg.DocsURL,
				"webmcp": map[string]string{
					"description":      "The same tools are also published in-page over WebMCP, so an agent in the user's browser can call them in the existing logged-in session with no connector and no API key. WebMCP has no declarative discovery of its own, which is why it is mentioned here.",
					"package":          "https://github.com/alertkick/alertkick-webmcp",
					"documentationUrl": "https://alertkick.com/docs/getting-started/webmcp-browser/",
				},
			},
		},
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

// streamableHandler builds the stateless streamable-HTTP MCP handler. Split
// out of Run so tests can exercise the transport directly.
func (s *Server) streamableHandler() http.Handler {
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
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
}
