package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listAlertsInput struct {
	Status string `json:"status,omitempty" jsonschema:"filter by status: open, acknowledged, or resolved"`
	Offset int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getAlertInput struct {
	UUID string `json:"uuid" jsonschema:"alert UUID (required)"`
}

type acknowledgeAlertInput struct {
	UUID string `json:"uuid" jsonschema:"alert UUID to acknowledge (required)"`
}

type resolveAlertInput struct {
	UUID string `json:"uuid" jsonschema:"alert UUID to resolve (required)"`
}

func RegisterAlertTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_alerts",
		Description: "List alerts with optional status filter. Returns alert name, status, severity, server, and timestamps.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listAlertsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListAlerts(in.Status, in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list alerts: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_alert",
		Description: "Get detailed information about a specific alert including its full history and associated server.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getAlertInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetAlert(in.UUID)
		if err != nil {
			return errorResult("Failed to get alert: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "acknowledge_alert",
		Description: "Acknowledge an open alert. This signals that someone is aware of and working on the issue.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in acknowledgeAlertInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.AcknowledgeAlerts([]string{in.UUID})
		if err != nil {
			return errorResult("Failed to acknowledge alert: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "resolve_alert",
		Description: "Resolve an alert, marking the issue as fixed. The alert will re-open if the check fails again.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in resolveAlertInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.ResolveAlerts([]string{in.UUID})
		if err != nil {
			return errorResult("Failed to resolve alert: " + err.Error())
		}
		return textResult(string(data))
	})
}
