package tools

import (
	"alertkick-mcp/client"
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type listChangesInput struct {
	Status   string `json:"status,omitempty" jsonschema:"filter by status: requested, approved, started, or completed"`
	HostUUID string `json:"host_uuid,omitempty" jsonschema:"filter by host UUID"`
	Offset   int    `json:"offset,omitempty" jsonschema:"result offset for pagination"`
	Limit    int    `json:"limit,omitempty" jsonschema:"max results to return (default 50, max 200)"`
}

type getChangeInput struct {
	UUID string `json:"uuid" jsonschema:"change UUID (required)"`
}

type createChangeInput struct {
	Title       string   `json:"title" jsonschema:"short title for the change (required)"`
	Description string   `json:"description,omitempty" jsonschema:"longer description of what the change does"`
	WindowStart string   `json:"window_start" jsonschema:"maintenance window start time in RFC3339 format, e.g. 2026-07-21T22:00:00Z (required)"`
	WindowEnd   string   `json:"window_end" jsonschema:"maintenance window end time in RFC3339 format, e.g. 2026-07-21T23:00:00Z (required)"`
	HostUUIDs   []string `json:"host_uuids" jsonschema:"AlertKick host UUIDs of the servers the change applies to, at least one (required)"`
}

type approveChangeInput struct {
	UUID string `json:"uuid" jsonschema:"change UUID to approve (required)"`
}

type startChangeInput struct {
	UUID string `json:"uuid" jsonschema:"change UUID to start (required)"`
}

type completeChangeInput struct {
	UUID string `json:"uuid" jsonschema:"change UUID to complete (required)"`
}

type verifyChangeInput struct {
	UUID string `json:"uuid" jsonschema:"change UUID to verify (required)"`
}

func RegisterChangeTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_changes",
		Annotations: annReadOnly("List change requests"),
		Description: "List change requests with optional status and host filters. Returns change title, status, verification status, maintenance window, and affected servers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listChangesInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListChanges(in.Status, in.HostUUID, in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list changes: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_change",
		Annotations: annReadOnly("Get change request"),
		Description: "Get detailed information about a specific change request, including its status, verification status (pending, running, clean, changes_detected, failed), maintenance window, and affected servers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getChangeInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetChange(in.UUID)
		if err != nil {
			return errorResult("Failed to get change: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_change",
		Annotations: annWrite("Create change request", false, false),
		Description: "Create a new change request in \"requested\" status with a title, maintenance window, and target servers. host_uuids are AlertKick host UUIDs, discoverable via the list_servers tool. The change must then be approved, started, and completed via the corresponding tools.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createChangeInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.Title == "" {
			return errorResult("title is required")
		}
		if in.WindowStart == "" {
			return errorResult("window_start is required")
		}
		if in.WindowEnd == "" {
			return errorResult("window_end is required")
		}
		if len(in.HostUUIDs) == 0 {
			return errorResult("host_uuids is required (at least one host UUID)")
		}
		data, err := c.CreateChange(in.Title, in.Description, in.WindowStart, in.WindowEnd, in.HostUUIDs)
		if err != nil {
			return errorResult("Failed to create change: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/change/show/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "approve_change",
		Annotations: annWrite("Approve change request", true, true),
		Description: "Approve a requested change, moving it to \"approved\" status so it can be started.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in approveChangeInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.ApproveChange(in.UUID)
		if err != nil {
			return errorResult("Failed to approve change: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "start_change",
		Annotations: annWrite("Start change request", true, true),
		Description: "Start an approved change. Side effect: this opens a maintenance window (SSH unlock) on the change's servers until the change's window end time.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in startChangeInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.StartChange(in.UUID)
		if err != nil {
			return errorResult("Failed to start change: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "complete_change",
		Annotations: annWrite("Complete change request", true, true),
		Description: "Complete a started change. Side effect: this re-locks the change's servers (closes the maintenance window) and starts an automatic FIM verification by the SRE agent. Poll get_change to see the verification_status.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in completeChangeInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.CompleteChange(in.UUID)
		if err != nil {
			return errorResult("Failed to complete change: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "verify_change",
		Annotations: annWrite("Verify change request", true, true),
		Description: "Re-run the FIM verification for a completed change. Returns the verification result including per-host changed-file lists.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in verifyChangeInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.VerifyChange(in.UUID)
		if err != nil {
			return errorResult("Failed to verify change: " + err.Error())
		}
		return textResult(string(data))
	})
}
