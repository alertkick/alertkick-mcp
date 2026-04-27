package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listIncidentsInput struct {
	Status   string `json:"status,omitempty" jsonschema:"filter by status: open, investigating, identified, monitoring, resolved"`
	Severity string `json:"severity,omitempty" jsonschema:"filter by severity: minor, major, critical"`
	Offset   int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit    int    `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getIncidentInput struct {
	UUID string `json:"uuid" jsonschema:"incident UUID (required)"`
}

func RegisterIncidentTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_incidents",
		Description: "List incidents with optional status and severity filters. Returns incident title, status, severity, and timeline.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listIncidentsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListIncidents(in.Status, in.Severity, in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list incidents: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_incident",
		Description: "Get detailed information about a specific incident including its full timeline of updates.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getIncidentInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetIncident(in.UUID)
		if err != nil {
			return errorResult("Failed to get incident: " + err.Error())
		}
		return textResult(string(data))
	})
}
