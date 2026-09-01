package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"alertkick-mcp/client"
	"alertkick-mcp/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callTool wires the real tool registrations to an in-memory MCP session
// backed by a fake api, so tests exercise the same code path the hosted
// connector runs: schema, requireWrite, client, result formatting.
func callTool(t *testing.T, api http.Handler, writeAllowed bool, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	cfg := &config.Config{InternalAPIURL: srv.URL, TenantDomain: "alertkick.test"}
	c := client.NewTenantClient(cfg, "test", "acme", "tok", writeAllowed)

	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	RegisterAll(s, c)
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "t"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	return res
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func TestAddServerOnFreePlanExplainsEntitlement(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/hosts/add" {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		json.NewEncoder(w).Encode(map[string]any{
			"error":   "agent_limit_reached",
			"message": "Server limit reached. Your plan allows 0 servers. Please upgrade to add more.",
			"usage":   map[string]any{"resource_type": "agents", "current": 0, "limit": 0, "limit_reached": true, "unlimited": false},
		})
	})
	res := callTool(t, api, true, "add_server", map[string]any{"server_name": "web-1"})
	if !res.IsError {
		t.Fatalf("expected tool error, got %q", resultText(res))
	}
	got := resultText(res)
	for _, want := range []string{"30-day trial", "Free plan has no server seats", "https://acme.alertkick.test/admin/plans"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "API returned status 402") {
		t.Errorf("raw 402 leaked into message: %q", got)
	}
}

func TestAddServerReturnsInstallCommandAndTrialNote(t *testing.T) {
	const cmd = "curl -sSL 'https://app.alertkick.test/app/agent-install/dab9sn20hc2c739me7c0/script/abc?sub=acme&reg=eu&exp=1' | sh"
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/hosts/add":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["server_name"] != "web-1" {
				t.Errorf("server_name = %q", in["server_name"])
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"uuid": "dab9sn20hc2c739me7c0", "agent_id": "eabc12345", "label": "web-1", "status": "nocheckin"})
		case "GET /api/v1/hosts/dab9sn20hc2c739me7c0/agent-install-universal":
			json.NewEncoder(w).Encode(map[string]any{"instructions": []map[string]string{{"heading": "Run this command on your server to install the agent", "command": cmd}}})
		case "GET /api/v1/billing/usage":
			json.NewEncoder(w).Encode(map[string]any{
				"usage": map[string]any{"agents": map[string]any{"current": 1, "limit": -1, "unlimited": true}},
				"plan":  map[string]any{"id": "trial", "name": "Trial"},
			})
		default:
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	res := callTool(t, api, true, "add_server", map[string]any{"server_name": "web-1"})
	if res.IsError {
		t.Fatalf("unexpected error: %q", resultText(res))
	}
	got := resultText(res)
	for _, want := range []string{cmd, "nocheckin", "eabc12345", "on the 30-day trial", "https://acme.alertkick.test/servers/dab9sn20hc2c739me7c0"} {
		if !strings.Contains(got, want) {
			t.Errorf("result lacks %q:\n%s", want, got)
		}
	}
}

func TestAddServerSucceedsWhenUsageLookupFails(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/hosts/add":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"uuid": "dab9sn20hc2c739me7c0", "agent_id": "e1", "label": "db-1", "status": "nocheckin"})
		case "GET /api/v1/hosts/dab9sn20hc2c739me7c0/agent-install-universal":
			json.NewEncoder(w).Encode(map[string]any{"instructions": []map[string]string{{"heading": "Run", "command": "curl x | sh"}}})
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	res := callTool(t, api, true, "add_server", map[string]any{"server_name": "db-1"})
	if res.IsError {
		t.Fatalf("usage lookup failure must not fail the add: %q", resultText(res))
	}
	if got := resultText(res); !strings.Contains(got, "curl x | sh") || strings.Contains(got, "trial") {
		t.Errorf("unexpected result: %q", got)
	}
}

func TestAddServerReadOnlyGrantIsRefusedBeforeCallingAPI(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("api must not be called on a read-only grant: %s %s", r.Method, r.URL.Path)
	})
	res := callTool(t, api, false, "add_server", map[string]any{"server_name": "web-1"})
	if !res.IsError || !strings.Contains(resultText(res), "read-only") {
		t.Fatalf("expected read-only refusal, got %q", resultText(res))
	}
}

func TestGetServerInstallCommand(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/hosts/dab9sn20hc2c739me7c0/agent-install-universal" {
			t.Errorf("unexpected call %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"instructions": []map[string]string{{"heading": "Run", "command": "curl y | sh"}}})
	})
	res := callTool(t, api, false, "get_server_install_command", map[string]any{"uuid": "dab9sn20hc2c739me7c0"})
	if res.IsError || !strings.Contains(resultText(res), "curl y | sh") {
		t.Fatalf("unexpected result: %q", resultText(res))
	}
}

func TestCreateMonitorMentionsMailType(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("api must not be called: %s %s", r.Method, r.URL.Path)
	})
	res := callTool(t, api, true, "create_monitor", map[string]any{"display_name": "x", "monitor_type": "", "url": "example.com"})
	if !res.IsError || !strings.Contains(resultText(res), "mail") {
		t.Fatalf("missing-type error should list mail: %q", resultText(res))
	}
}
