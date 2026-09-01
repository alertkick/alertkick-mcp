package tools

import (
	"alertkick-mcp/client"
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

type addServerInput struct {
	ServerName           string `json:"server_name" jsonschema:"name for the server as it should appear in AlertKick, usually its hostname (required)"`
	EscalationPolicyUUID string `json:"escalation_policy_uuid,omitempty" jsonschema:"escalation policy to route this server's alerts to (optional; defaults to the workspace default policy)"`
}

type getServerInstallCommandInput struct {
	UUID string `json:"uuid" jsonschema:"server UUID from add_server or list_servers (required)"`
}

// serverPlanNote is the sentence every server tool uses to explain the
// entitlement. It is in the tool description (so the model knows before it
// calls) and in the 402 translation (so the user knows why it failed).
const serverPlanNote = "Agent-based server monitoring is included in the 30-day trial and on paid plans; the Free plan has no server seats."

func RegisterServerTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "add_server",
		Annotations: annWrite("Add server", false, false),
		Description: "Register a Linux server for agent-based monitoring (CPU, memory, disk, load, processes, Docker containers, SSH logins, eBPF security detections, file integrity) and return the one-line install command to run on it. " + serverPlanNote + " On a plan without a free seat this tool returns an upgrade link instead of creating anything. The server shows as 'nocheckin' until the agent installs and reports in; use get_server_install_command to fetch the command again later (the link inside it expires after 24 hours).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in addServerInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		name := strings.TrimSpace(in.ServerName)
		if name == "" {
			return errorResult("server_name is required")
		}
		data, err := c.AddHost(name, in.EscalationPolicyUUID)
		if err != nil {
			if msg, ok := planLimitMessage(c, err, "servers"); ok {
				return errorResult(msg)
			}
			return errorResult("Failed to add server: " + err.Error())
		}
		var host struct {
			UUID    string `json:"uuid"`
			AgentID string `json:"agent_id"`
			Label   string `json:"label"`
			Status  string `json:"status"`
		}
		if jerr := json.Unmarshal(data, &host); jerr != nil || host.UUID == "" {
			return textResult(string(data))
		}

		var b strings.Builder
		fmt.Fprintf(&b, "Server %q registered (uuid %s, agent id %s). Status is %q until the agent reports in.\n", host.Label, host.UUID, host.AgentID, host.Status)
		b.WriteString(installCommandText(c, host.UUID))
		b.WriteString(trialNote(c))
		return textResult(b.String())
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_server_install_command",
		Annotations: annReadOnly("Get server install command"),
		Description: "Return the one-line agent install command for a server that was already added (add_server or the dashboard) but has no agent reporting yet, or whose agent needs reinstalling. The signed link inside the command is valid for 24 hours. " + serverPlanNote,
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getServerInstallCommandInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		return textResult(installCommandText(c, in.UUID))
	})

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

// installCommandText fetches the universal (OS-detecting) install command
// for a host and formats it for a person to paste. The Windows path is a
// full PowerShell script the api only renders per package, so we point at
// the dashboard for that rather than dumping it into chat.
func installCommandText(c *client.Client, hostUUID string) string {
	inst, err := c.GetUniversalInstallCommand(hostUUID)
	if err != nil {
		return fmt.Sprintf("\nCould not fetch the install command: %s\nOpen the server in AlertKick to get it: %s/servers/%s\n", err.Error(), c.PublicUIBaseURL(), hostUUID)
	}
	var b strings.Builder
	for _, i := range inst.Instructions {
		if i.Command != "" {
			fmt.Fprintf(&b, "\n%s (as root, Linux deb/rpm/tar.gz on amd64 or arm64):\n\n    %s\n", i.Heading, i.Command)
		} else if i.Content != "" {
			fmt.Fprintf(&b, "\n%s:\n\n%s\n", i.Heading, i.Content)
		}
	}
	if b.Len() == 0 {
		fmt.Fprintf(&b, "\nNo install command returned. Open the server in AlertKick to get it: %s/servers/%s\n", c.PublicUIBaseURL(), hostUUID)
	}
	fmt.Fprintf(&b, "\nThe link in the command expires in 24 hours (call get_server_install_command for a fresh one). Windows servers: use the install page at %s/servers/%s.\n", c.PublicUIBaseURL(), hostUUID)
	fmt.Fprintf(&b, "\nView it in AlertKick: %s/servers/%s", c.PublicUIBaseURL(), hostUUID)
	return b.String()
}

// trialNote appends a plan reminder after a successful add. Best-effort:
// a failed usage lookup must never turn a created server into an error.
func trialNote(c *client.Client) string {
	usage, err := c.GetBillingUsage()
	if err != nil {
		return ""
	}
	switch usage.Plan.ID {
	case "trial":
		return fmt.Sprintf("\n\nNote: this workspace is on the 30-day trial. Adding servers needs a paid plan once the trial ends; existing servers are kept. Plans: %s/admin/plans", c.PublicUIBaseURL())
	case "free", "":
		return ""
	}
	if a, ok := usage.Usage["agents"]; ok && !a.Unlimited && a.Limit > 0 {
		return fmt.Sprintf("\n\nServer seats used on the %s plan: %d of %d.", usage.Plan.Name, a.Current, a.Limit)
	}
	return ""
}

// planLimitMessage turns a plan-limit 402 into a sentence that says what
// the plan allows and where to upgrade, instead of the raw JSON. ok is
// false for any other error so the caller keeps its generic wording.
func planLimitMessage(c *client.Client, err error, resource string) (string, bool) {
	pl, ok := client.AsPlanLimit(err)
	if !ok {
		return "", false
	}
	upgrade := pl.UpgradeURL
	if upgrade == "" || strings.HasPrefix(upgrade, "/") {
		upgrade = c.PublicUIBaseURL() + "/admin/plans"
	}
	switch {
	case pl.Error == "subscription_required":
		return "This workspace has not chosen a plan yet, so nothing can be created. Pick a plan (the trial is free for 30 days): " + upgrade, true
	case pl.Usage != nil && pl.Usage.Limit == 0 && !pl.Usage.Unlimited:
		return fmt.Sprintf("Not created: the workspace's current plan includes no %s. %s Upgrade: %s", resource, serverPlanNote, upgrade), true
	case pl.Usage != nil:
		return fmt.Sprintf("Not created: the plan's %s limit is reached (%d of %d in use). Upgrade for more: %s", resource, pl.Usage.Current, pl.Usage.Limit, upgrade), true
	}
	return fmt.Sprintf("Not created: %s Upgrade: %s", pl.Message, upgrade), true
}
