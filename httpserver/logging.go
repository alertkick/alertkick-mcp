package httpserver

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Access and tool-call logging. One JSON object per line on stdout so the
// Docker log tail (Alloy -> VictoriaLogs) gets structured fields without a
// parse stage; the api container uses the same shape ("_msg":"request").
//
// Health probes are skipped: Traefik and the fleet poll them constantly and
// they carry no operator signal.

var jsonLog = json.NewEncoder(os.Stdout)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Flush keeps streaming (SSE) responses working through the recorder.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func isHealthPath(p string) bool {
	return p == "/healthz" || p == "/livez" || p == "/readyz"
}

// withAccessLog logs every non-health HTTP request. Tenant/user come from
// the verified claims placed on the context by requireAuth, so an
// unauthenticated 401 logs with empty tenant fields.
func withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isHealthPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		entry := map[string]any{
			"msg":          "request",
			"level":        "info",
			"time":         start.UTC().Format(time.RFC3339),
			"method":       r.Method,
			"request_url":  r.URL.RequestURI(),
			"status_code":  rec.status,
			"bytes":        rec.bytes,
			"process_time": float64(time.Since(start).Microseconds()) / 1000.0, // ms
			"client_ip":    clientIP(r),
			"user_agent":   r.UserAgent(),
		}
		if c, ok := r.Context().Value(claimsKey).(*AccessClaims); ok && c != nil {
			entry["tenant"] = c.Subdomain
			entry["username"] = c.Username
			entry["client_id"] = c.ClientID
			entry["scope"] = c.Scope
		}
		if rec.status >= 500 {
			entry["level"] = "error"
		} else if rec.status >= 400 {
			entry["level"] = "warn"
		}
		if err := jsonLog.Encode(entry); err != nil {
			log.Printf("access log encode: %v", err)
		}
	})
}

// clientIP prefers the edge-supplied X-Forwarded-For (Traefik sets it; the
// first hop is the caller) and falls back to the socket peer.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if rip := r.Header.Get("X-Real-Ip"); rip != "" {
		return rip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// toolCallLogger is an MCP receiving middleware that records every
// tools/call with its outcome. Arguments are deliberately NOT logged: they
// can carry customer monitor URLs, hostnames and free-text.
func toolCallLogger(claims *AccessClaims) mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			start := time.Now()
			res, err := next(ctx, method, req)

			entry := map[string]any{
				"msg":          "tool_call",
				"level":        "info",
				"time":         start.UTC().Format(time.RFC3339),
				"process_time": float64(time.Since(start).Microseconds()) / 1000.0, // ms
				"tenant":       claims.Subdomain,
				"username":     claims.Username,
				"client_id":    claims.ClientID,
			}
			if ctr, ok := req.(*mcp.CallToolRequest); ok && ctr.Params != nil {
				entry["tool"] = ctr.Params.Name
			}
			switch {
			case err != nil:
				entry["level"] = "error"
				entry["outcome"] = "protocol_error"
				entry["error"] = err.Error()
			default:
				entry["outcome"] = "ok"
				if ctres, ok := res.(*mcp.CallToolResult); ok && ctres != nil && ctres.IsError {
					entry["level"] = "warn"
					entry["outcome"] = "tool_error"
				}
			}
			if encErr := jsonLog.Encode(entry); encErr != nil {
				log.Printf("tool log encode: %v", encErr)
			}
			return res, err
		}
	}
}
