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

type createMonitorInput struct {
	Locations                []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName              string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	MonitorType              string   `json:"monitor_type" jsonschema:"one of: http, api, dns, tcp, domain, mail (required). Use 'domain' for domain registration expiry, 'http' with ssl_cert_monitoring for HTTPS certificate expiry"`
	URL                      string   `json:"url" jsonschema:"target to check: full URL for http/api, hostname for dns/tcp, registrable domain for domain/mail (required)"`
	HTTPMethod               string   `json:"http_method,omitempty" jsonschema:"HTTP method for http/api monitors (default GET)"`
	CheckIntervalSeconds     int      `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 300; plans may enforce a higher floor)"`
	TimeoutSeconds           int      `json:"timeout_seconds,omitempty" jsonschema:"per-check timeout in seconds (default 30)"`
	ExpectedStatusCode       int      `json:"expected_status_code,omitempty" jsonschema:"expected HTTP status for http/api monitors (default 200)"`
	ExpectedResponseContains string   `json:"expected_response_contains,omitempty" jsonschema:"alert unless the response body contains this string (http/api only)"`
	TCPPort                  int      `json:"tcp_port,omitempty" jsonschema:"port to connect to (required for tcp monitors)"`
	DNSRecordType            string   `json:"dns_record_type,omitempty" jsonschema:"DNS record type for dns monitors: A, AAAA, CNAME, MX, TXT, NS"`
	ExpectedDNSHost          string   `json:"expected_dns_host,omitempty" jsonschema:"expected resolved value for dns monitors"`
	SSLCertMonitoring        bool     `json:"ssl_cert_monitoring,omitempty" jsonschema:"also monitor the TLS certificate on https URLs"`
	SSLCertExpiryAlertDays   int      `json:"ssl_cert_expiry_alert_days,omitempty" jsonschema:"alert this many days before the TLS certificate expires (default 14)"`
	DomainExpiryAlertDays    int      `json:"domain_expiry_alert_days,omitempty" jsonschema:"for domain monitors: alert this many days before the registration expires (default 30, max 365)"`
	ResponseTimeAlertMs      int      `json:"response_time_alert_ms,omitempty" jsonschema:"alert when successful checks are slower than this many milliseconds (http/api only; 0 = disabled)"`
	FailureThreshold         int      `json:"failure_threshold,omitempty" jsonschema:"consecutive failures before alerting (default 3)"`
}

func RegisterMonitorTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_monitors",
		Annotations: annReadOnly("List monitors"),
		Description: "List all HTTP/TCP/DNS/SSL monitors with their current status, response times, and check intervals.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in listMonitorsInput) (*mcp.CallToolResult, any, error) {
		limit := clampLimit(in.Limit, 50, 200)
		data, err := c.ListMonitors(in.Offset, limit)
		if err != nil {
			return errorResult("Failed to list monitors: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_monitor",
		Annotations: annReadOnly("Get monitor"),
		Description: "Get detailed information about a specific monitor including its configuration, check history, and assigned pollers.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getMonitorInput) (*mcp.CallToolResult, any, error) {
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.GetMonitor(in.UUID)
		if err != nil {
			return errorResult("Failed to get monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_poller_locations",
		Annotations: annReadOnly("List poller locations"),
		Description: "List the poller locations monitors can run from: AlertKick's system locations (by region) plus the account's own on-prem pollers. Use the location_key values in the locations field of the create_*_monitor tools. A monitor created without locations runs from the account's home-region system location.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in struct{}) (*mcp.CallToolResult, any, error) {
		data, err := c.ListPollerLocations()
		if err != nil {
			return errorResult("Failed to list poller locations: " + err.Error())
		}
		return textResult(string(data))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_monitor",
		Annotations: annWrite("Create monitor", false, false),
		Description: "Generic monitor creator; prefer the typed tools (create_https_monitor, create_dns_monitor, create_tcp_monitor, create_domain_expiry_monitor, create_mail_monitor) when one fits. Types: 'http'/'api' check a URL (optionally with ssl_cert_monitoring for HTTPS certificate expiry), 'dns' checks record resolution, 'tcp' checks a port, 'domain' checks domain registration expiry, 'mail' checks a domain's email posture (MX/SPF/DMARC/DKIM/blocklists). Only display_name, monitor_type and url are required (url is the hostname or domain for dns/tcp/domain/mail); sensible defaults cover the rest. Alerts route to the account's default escalation policy.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" {
			return errorResult("display_name is required")
		}
		if in.MonitorType == "" {
			return errorResult("monitor_type is required (http, api, dns, tcp, domain, or mail)")
		}
		if in.URL == "" {
			return errorResult("url is required")
		}
		if in.MonitorType == "tcp" && in.TCPPort <= 0 {
			return errorResult("tcp_port is required for tcp monitors")
		}

		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           in.MonitorType,
			"url":                    in.URL,
			"timeout_seconds":        defaultInt(in.TimeoutSeconds, 30),
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 300),
			"expected_status_code":   defaultInt(in.ExpectedStatusCode, 200),
		}
		if in.MonitorType == "http" || in.MonitorType == "api" {
			payload["http_method"] = defaultString(in.HTTPMethod, "GET")
		}
		if in.ExpectedResponseContains != "" {
			payload["expected_response_contains"] = in.ExpectedResponseContains
		}
		if in.TCPPort > 0 {
			payload["tcp_port"] = in.TCPPort
		}
		if in.DNSRecordType != "" {
			payload["dns_record_type"] = in.DNSRecordType
		}
		if in.ExpectedDNSHost != "" {
			payload["expected_dns_host"] = in.ExpectedDNSHost
		}
		if in.SSLCertMonitoring || in.SSLCertExpiryAlertDays > 0 {
			payload["ssl_cert_monitoring"] = true
			if in.SSLCertExpiryAlertDays > 0 {
				payload["ssl_cert_expiry_alert_days"] = in.SSLCertExpiryAlertDays
			}
		}
		if in.DomainExpiryAlertDays > 0 {
			payload["domain_expiry_alert_days"] = in.DomainExpiryAlertDays
		}
		if in.ResponseTimeAlertMs > 0 {
			payload["response_time_alert_ms"] = in.ResponseTimeAlertMs
		}
		if in.FailureThreshold > 0 {
			payload["failure_threshold"] = in.FailureThreshold
		}

		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "pause_monitor",
		Annotations: annWrite("Pause monitor", true, true),
		Description: "Pause a monitor: checks stop and no alerts fire until it is resumed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.PauseMonitor(in.UUID)
		if err != nil {
			return errorResult("Failed to pause monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "resume_monitor",
		Annotations: annWrite("Resume monitor", true, true),
		Description: "Resume a paused monitor so checks and alerting start again.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.ResumeMonitor(in.UUID)
		if err != nil {
			return errorResult("Failed to resume monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "delete_monitor",
		Annotations: annWrite("Delete monitor", true, true),
		Description: "Permanently delete a monitor and stop all its checks.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in getMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.UUID == "" {
			return errorResult("uuid is required")
		}
		data, err := c.DeleteMonitor(in.UUID)
		if err != nil {
			return errorResult("Failed to delete monitor: " + err.Error())
		}
		// No UI link here on purpose: the monitor no longer exists.
		return textResult(string(data))
	})
}
