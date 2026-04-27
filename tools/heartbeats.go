package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listHeartbeatsInput struct {
	Offset int `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit  int `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

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
}
