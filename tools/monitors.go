package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listMonitorsInput struct {
	Offset int `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit  int `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getMonitorInput struct {
	UUID string `json:"uuid" jsonschema:"monitor UUID (required)"`
}

func RegisterMonitorTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_monitors",
		Description: "List all HTTP/TCP/DNS/SSL monitors with their current status, response times, and check intervals.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listMonitorsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListMonitors(in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list monitors: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_monitor",
		Description: "Get detailed information about a specific monitor including its configuration, check history, and assigned pollers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getMonitorInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetMonitor(in.UUID)
		if err != nil {
			return errorResult("Failed to get monitor: " + err.Error())
		}
		return textResult(string(data))
	})
}
