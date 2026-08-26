package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listServersInput struct {
	Offset int `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit  int `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getServerInput struct {
	UUID string `json:"uuid" jsonschema:"server UUID (required)"`
}

type getServerContainersInput struct {
	UUID string `json:"uuid" jsonschema:"server UUID (required)"`
}

func RegisterServerTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_servers",
		Annotations: annReadOnly("List servers"),
		Description: "List all monitored servers with their status, hostname, IP addresses, OS info, and agent version. Supports pagination.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listServersInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListHosts(in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list servers: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_server",
		Annotations: annReadOnly("Get server"),
		Description: "Get detailed information about a specific server including checks, host info, uptime, and agent details.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getServerInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetHost(in.UUID)
		if err != nil {
			return errorResult("Failed to get server: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_server_containers",
		Annotations: annReadOnly("Get server containers"),
		Description: "Get Docker containers running on a specific server, including status, CPU, memory, and network stats.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getServerContainersInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetHostContainers(in.UUID)
		if err != nil {
			return errorResult("Failed to get containers: " + err.Error())
		}
		return textResult(string(data))
	})
}
