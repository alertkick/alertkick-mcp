package tools

import (
	"alertkick-mcp/client"
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listHeartbeatsInput struct {
	Offset int `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit  int `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getHeartbeatInput struct {
	UUID string `json:"uuid" jsonschema:"heartbeat UUID (required)"`
}

type createHeartbeatInput struct {
	Slug            string `json:"slug" jsonschema:"unique identifier for the heartbeat, e.g. 'nightly-backup' (required; letters, digits, dot, dash, underscore, max 64 chars)"`
	Name            string `json:"name,omitempty" jsonschema:"display name (defaults to the slug)"`
	IntervalSeconds int    `json:"interval_seconds,omitempty" jsonschema:"expected ping interval in seconds (default 86400 = daily)"`
	GraceSeconds    int    `json:"grace_seconds,omitempty" jsonschema:"grace period in seconds before a late ping counts as missed (default 3600)"`
}

var heartbeatSlugPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func RegisterHeartbeatTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_heartbeats",
		Description: "List all heartbeat monitors. Heartbeats track cron jobs and scheduled tasks by expecting periodic pings.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listHeartbeatsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListHeartbeats(in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list heartbeats: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_heartbeat",
		Description: "Get a heartbeat's full configuration and state, including its ping key and current health.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getHeartbeatInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetHeartbeat(in.UUID)
		if err != nil {
			return errorResult("Failed to get heartbeat: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_heartbeat",
		Description: "Create a heartbeat monitor for a cron job or scheduled task. Idempotent by slug: if a heartbeat with this slug exists it is pinged instead of duplicated. Creation records a first ping and arms monitoring immediately, so the next real ping is expected within interval_seconds + grace_seconds. Returns the ping command to embed in the job.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createHeartbeatInput) (*mcp.CallToolResult, any, error) {
		if in.Slug == "" {
			return errorResult("slug is required")
		}
		if !heartbeatSlugPattern.MatchString(in.Slug) {
			return errorResult("slug must start with a letter or digit and contain only letters, digits, '.', '-', '_' (max 64 chars)")
		}
		autoPing, err := c.AutoPingHeartbeat(in.Slug, in.IntervalSeconds, in.GraceSeconds, in.Name)
		if err != nil {
			return errorResult("Failed to create heartbeat: " + err.Error())
		}

		data, err := c.GetHeartbeat(autoPing.UUID)
		if err != nil {
			return errorResult(fmt.Sprintf("Heartbeat %s exists (uuid %s) but fetching its details failed: %s", in.Slug, autoPing.UUID, err.Error()))
		}
		var hb struct {
			APIKey string `json:"api_key"`
		}
		_ = json.Unmarshal(data, &hb)

		verb := "created and armed"
		if !autoPing.Created {
			verb = "already existed; recorded a ping instead"
		}
		text := fmt.Sprintf(`Heartbeat %q %s.

%s

Ping it from the job using its scoped key (safe to embed in scripts, valid only for this heartbeat):

  curl -fsS -H "X-Heartbeat-Key: %s" "%s/hb/ping/%s"

Or ping by slug with the account API key (also creates the heartbeat if missing):

  curl -fsS -H "X-API-Key: $ALERTKICK_API_KEY" "%s/hb/auto/%s"`,
			in.Slug, verb, string(data), hb.APIKey, c.BaseURL(), autoPing.UUID, c.BaseURL(), autoPing.Slug)
		return textResult(text)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "enable_heartbeat",
		Description: "Enable a disabled heartbeat so missed pings alert again.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getHeartbeatInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.EnableHeartbeat(in.UUID)
		if err != nil {
			return errorResult("Failed to enable heartbeat: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "disable_heartbeat",
		Description: "Disable a heartbeat so missed pings stop alerting (e.g. while the job is intentionally stopped).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getHeartbeatInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.DisableHeartbeat(in.UUID)
		if err != nil {
			return errorResult("Failed to disable heartbeat: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_heartbeat",
		Description: "Permanently delete a heartbeat monitor. Its ping URL stops working.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getHeartbeatInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.DeleteHeartbeat(in.UUID)
		if err != nil {
			return errorResult("Failed to delete heartbeat: " + err.Error())
		}
		return textResult(string(data))
	})
}
