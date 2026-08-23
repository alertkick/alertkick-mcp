package tools

import (
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
