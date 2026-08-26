package tools

import (
	"alertkick-mcp/client"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func errorResult(msg string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: msg},
		},
		IsError: true,
	}, nil, nil
}

func textResult(text string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}, nil, nil
}

func defaultInt(value, defaultVal int) int {
	if value <= 0 {
		return defaultVal
	}
	return value
}

func defaultString(value, defaultVal string) string {
	if value == "" {
		return defaultVal
	}
	return value
}

func clampLimit(limit, defaultVal, maxVal int) int {
	if limit <= 0 {
		return defaultVal
	}
	if limit > maxVal {
		return maxVal
	}
	return limit
}

// RegisterAll registers every tool group on the server. Both run modes use
// this so the hosted connector and the stdio binary never drift.
func RegisterAll(s *mcp.Server, c *client.Client) {
	RegisterServerTools(s, c)
	RegisterAlertTools(s, c)
	RegisterSecurityEventTools(s, c)
	RegisterMonitorTools(s, c)
	RegisterMonitorTypeTools(s, c)
	RegisterHeartbeatTools(s, c)
	RegisterIncidentTools(s, c)
	RegisterChangeTools(s, c)
}

// requireWrite returns a tool error result when the connection is
// read-only (OAuth grant without the "write" scope). The api enforces the
// same rule server-side; this just gives the model a clear message.
func requireWrite(c *client.Client) (*mcp.CallToolResult, any, error) {
	if c.CanWrite() {
		return nil, nil, nil
	}
	return errorResult("This AlertKick connection was granted read-only access. Reconnect with the write scope to use this tool.")
}

// annReadOnly builds the annotation block for read-only tools. Directory
// review requires every tool to carry a title plus the applicable
// readOnly/destructive hint; read-only tools may run without per-call
// confirmation in Claude.
func annReadOnly(title string) *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{
		Title:         title,
		ReadOnlyHint:  true,
		OpenWorldHint: &f,
	}
}

// annWrite builds the annotation block for state-changing tools.
// destructive=false marks purely additive creates; everything that
// modifies or deletes existing state sets it true.
func annWrite(title string, destructive, idempotent bool) *mcp.ToolAnnotations {
	f := false
	d := destructive
	return &mcp.ToolAnnotations{
		Title:           title,
		DestructiveHint: &d,
		IdempotentHint:  idempotent,
		OpenWorldHint:   &f,
	}
}
