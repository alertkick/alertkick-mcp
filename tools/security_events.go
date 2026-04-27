package tools

import (
	"alertkick-mcp/client"
	"context"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listSecurityEventsInput struct {
	Duration   string `json:"duration,omitempty" jsonschema:"time range, e.g. 1h, 24h, 7d (default 24h)"`
	Priority   string `json:"priority,omitempty" jsonschema:"filter by priority: emergency, alert, critical, error, warning, notice, informational, debug"`
	AgentType  string `json:"agent_type,omitempty" jsonschema:"filter by agent type"`
	Rule       string `json:"rule,omitempty" jsonschema:"filter by rule name"`
	HostUUID   string `json:"host_uuid,omitempty" jsonschema:"filter by server UUID"`
	LLMVerdict string `json:"llm_verdict,omitempty" jsonschema:"filter by AI verdict: malicious, suspicious, benign, informational"`
	EventClass string `json:"event_class,omitempty" jsonschema:"filter by event class"`
	Limit      int    `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 500)"`
	Offset     int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
}

type getSecurityEventStatsInput struct {
	Duration string `json:"duration,omitempty" jsonschema:"time range for stats, e.g. 1h, 24h, 7d (default 24h)"`
}

func RegisterSecurityEventTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_security_events",
		Description: "List security events (eBPF/Falco detections) with optional filters for priority, rule, host, AI verdict, and time range.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listSecurityEventsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 500)
		params := url.Values{}
		params.Set("limit", fmt.Sprintf("%d", limit))
		params.Set("offset", fmt.Sprintf("%d", in.Offset))
		if in.Duration != "" {
			params.Set("duration", in.Duration)
		}
		if in.Priority != "" {
			params.Set("priority", in.Priority)
		}
		if in.AgentType != "" {
			params.Set("agent_type", in.AgentType)
		}
		if in.Rule != "" {
			params.Set("rule", in.Rule)
		}
		if in.HostUUID != "" {
			params.Set("host_uuid", in.HostUUID)
		}
		if in.LLMVerdict != "" {
			params.Set("llm_verdict", in.LLMVerdict)
		}
		if in.EventClass != "" {
			params.Set("event_class", in.EventClass)
		}
		data, err := c.ListSecurityEvents(params)
		if err != nil {
			return errorResult("Failed to list security events: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_security_event_stats",
		Description: "Get aggregate statistics for security events: counts by priority, rule, host, and AI verdict over a time range.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getSecurityEventStatsInput) (*mcp.CallToolResult, any, error) {
		data, err := c.GetSecurityEventsStats(in.Duration)
		if err != nil {
			return errorResult("Failed to get security event stats: " + err.Error())
		}
		return textResult(string(data))
	})
}
