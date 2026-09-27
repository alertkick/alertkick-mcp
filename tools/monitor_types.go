package tools

// Purpose-built creators for the common monitor types. create_monitor
// (monitors.go) remains as the generic escape hatch; these narrow tools
// give assistants an obvious, hard-to-misuse path for the monitoring jobs
// people actually ask for: "watch this HTTPS endpoint and its cert",
// "watch this DNS record", "tell me before the domain expires",
// "check this port stays open", "tell me if this MCP server's tools change".

import (
	"alertkick-mcp/client"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type createHTTPSMonitorInput struct {
	Locations                []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName              string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	URL                      string   `json:"url" jsonschema:"full URL to check, e.g. https://example.com/health (required)"`
	CheckIntervalSeconds     int      `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 300)"`
	ExpectedStatusCode       int      `json:"expected_status_code,omitempty" jsonschema:"expected HTTP status (default 200)"`
	ExpectedResponseContains string   `json:"expected_response_contains,omitempty" jsonschema:"alert unless the response body contains this string"`
	MonitorSSLCert           *bool    `json:"monitor_ssl_cert,omitempty" jsonschema:"also alert before the TLS certificate expires (default true for https URLs)"`
	SSLCertExpiryAlertDays   int      `json:"ssl_cert_expiry_alert_days,omitempty" jsonschema:"days before certificate expiry to alert (default 14)"`
	ResponseTimeAlertMs      int      `json:"response_time_alert_ms,omitempty" jsonschema:"alert when successful checks are slower than this many milliseconds (0 = disabled)"`
	FailureThreshold         int      `json:"failure_threshold,omitempty" jsonschema:"consecutive failures before alerting (default 3)"`
}

type createDNSMonitorInput struct {
	Locations            []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName          string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	Hostname             string   `json:"hostname" jsonschema:"DNS name to resolve, e.g. www.example.com (required)"`
	RecordType           string   `json:"record_type,omitempty" jsonschema:"record type: A, AAAA, CNAME, MX, TXT or NS (default A)"`
	ExpectedValue        string   `json:"expected_value,omitempty" jsonschema:"alert when the record no longer resolves to this value (optional; without it the check alerts only on resolution failure, and AlertKick still tracks answer changes per location)"`
	CheckIntervalSeconds int      `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 300)"`
}

type createDomainExpiryMonitorInput struct {
	Locations             []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName           string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	Domain                string   `json:"domain" jsonschema:"registrable domain to watch, e.g. example.com (required)"`
	DomainExpiryAlertDays int      `json:"domain_expiry_alert_days,omitempty" jsonschema:"days before registration expiry to alert (default 30, max 365)"`
}

type createMailMonitorInput struct {
	Locations            []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName          string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	Domain               string   `json:"domain" jsonschema:"domain that sends or receives mail, e.g. example.com (required)"`
	RequireDmarcPolicy   string   `json:"require_dmarc_policy,omitempty" jsonschema:"minimum DMARC policy to require: none, quarantine or reject (optional; the check always fails on missing SPF/DMARC, +all, PermError or a blocklist listing)"`
	CheckIntervalSeconds int      `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 3600)"`
}

type createMCPMonitorInput struct {
	Locations            []string          `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName          string            `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	URL                  string            `json:"url" jsonschema:"the MCP endpoint URL, e.g. https://mcp.example.com/mcp (required)"`
	Transport            string            `json:"transport,omitempty" jsonschema:"streamable-http (default) or sse for legacy HTTP+SSE servers"`
	AuthMode             string            `json:"auth_mode,omitempty" jsonschema:"none (default), header (static headers such as Authorization or X-API-Key), or oauth (checks the OAuth discovery chain only; no login, so the tool list is not checked)"`
	Headers              map[string]string `json:"headers,omitempty" jsonschema:"header name -> value, only for auth_mode header; values are stored encrypted. Secrets can also be added later in the AlertKick web app instead of here"`
	DriftPolicy          string            `json:"drift_policy,omitempty" jsonschema:"alert (default): changes since the approved baseline fail the check; record: changes are logged as events only"`
	ExpectedTools        []string          `json:"expected_tools,omitempty" jsonschema:"tool names that must be present; a missing one fails the check"`
	MaxTools             int               `json:"max_tools,omitempty" jsonschema:"fail when the server lists more tools than this (0 = no cap)"`
	CheckIntervalSeconds int               `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 600)"`
	TimeoutSeconds       int               `json:"timeout_seconds,omitempty" jsonschema:"per-check timeout in seconds (default 20)"`
}

type createTCPMonitorInput struct {
	Locations            []string `json:"locations,omitempty" jsonschema:"poller location keys to check from (optional; defaults to the account's home-region location; use list_poller_locations to see the keys)"`
	DisplayName          string   `json:"display_name" jsonschema:"human-readable name for the monitor (required)"`
	Host                 string   `json:"host" jsonschema:"hostname or IP to connect to (required)"`
	Port                 int      `json:"port" jsonschema:"TCP port to connect to (required)"`
	CheckIntervalSeconds int      `json:"check_interval_seconds,omitempty" jsonschema:"seconds between checks (default 300)"`
	FailureThreshold     int      `json:"failure_threshold,omitempty" jsonschema:"consecutive failures before alerting (default 3)"`
}

// RegisterMonitorTypeTools registers the typed monitor creators.
func RegisterMonitorTypeTools(s *mcp.Server, c *client.Client) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_https_monitor",
		Annotations: annWrite("Create HTTPS/uptime monitor", false, false),
		Description: "Create an uptime monitor for a website or API endpoint. Checks the URL on an interval from AlertKick's poller locations and alerts on failures; for https URLs it also monitors the TLS certificate and alerts before it expires. Alerts route to the account's default escalation policy.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createHTTPSMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" || in.URL == "" {
			return errorResult("display_name and url are required")
		}
		sslMonitoring := strings.HasPrefix(strings.ToLower(in.URL), "https://")
		if in.MonitorSSLCert != nil {
			sslMonitoring = *in.MonitorSSLCert
		}
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "http",
			"url":                    in.URL,
			"http_method":            "GET",
			"expected_status_code":   defaultInt(in.ExpectedStatusCode, 200),
			"ssl_cert_monitoring":    sslMonitoring,
			"timeout_seconds":        30,
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 300),
		}
		if in.ExpectedResponseContains != "" {
			payload["expected_response_contains"] = in.ExpectedResponseContains
		}
		if in.SSLCertExpiryAlertDays > 0 {
			payload["ssl_cert_expiry_alert_days"] = in.SSLCertExpiryAlertDays
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
		Name:        "create_dns_monitor",
		Annotations: annWrite("Create DNS monitor", false, false),
		Description: "Create a DNS monitor that resolves a record on an interval and alerts on resolution failure — or, when expected_value is set, whenever the answer no longer matches it (hijack/misconfiguration detection). Answer changes are tracked per poller location either way.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createDNSMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" || in.Hostname == "" {
			return errorResult("display_name and hostname are required")
		}
		recordType := strings.ToUpper(defaultString(in.RecordType, "A"))
		switch recordType {
		case "A", "AAAA", "CNAME", "MX", "TXT", "NS":
		default:
			return errorResult("record_type must be one of A, AAAA, CNAME, MX, TXT, NS")
		}
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "dns",
			"url":                    in.Hostname,
			"dns_record_type":        recordType,
			"timeout_seconds":        30,
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 300),
		}
		if in.ExpectedValue != "" {
			payload["expected_dns_host"] = in.ExpectedValue
		}
		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create DNS monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_domain_expiry_monitor",
		Annotations: annWrite("Create domain-expiry monitor", false, false),
		Description: "Create a domain registration expiry monitor. AlertKick checks the domain's RDAP record daily and alerts ahead of the expiry date; it also surfaces registrar, transfer-lock status, nameservers and mail posture (MX/SPF/DMARC), and alerts if the transfer lock is removed.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createDomainExpiryMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" || in.Domain == "" {
			return errorResult("display_name and domain are required")
		}
		domain := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(in.Domain)), "https://"), "http://")
		domain = strings.TrimSuffix(strings.Split(domain, "/")[0], ".")
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "domain",
			"url":                    domain,
			"timeout_seconds":        30,
			"check_interval_seconds": 86400, // RDAP data changes daily at most
		}
		if in.DomainExpiryAlertDays > 0 {
			payload["domain_expiry_alert_days"] = in.DomainExpiryAlertDays
		}
		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create domain-expiry monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_tcp_monitor",
		Annotations: annWrite("Create TCP port monitor", false, false),
		Description: "Create a TCP monitor that opens a connection to host:port on an interval and alerts when the port stops accepting connections (databases, mail servers, game servers, anything not speaking HTTP).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createTCPMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" || in.Host == "" {
			return errorResult("display_name and host are required")
		}
		if in.Port <= 0 || in.Port > 65535 {
			return errorResult(fmt.Sprintf("port must be 1-65535, got %d", in.Port))
		}
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "tcp",
			"url":                    in.Host,
			"tcp_port":               in.Port,
			"timeout_seconds":        30,
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 300),
		}
		if in.FailureThreshold > 0 {
			payload["failure_threshold"] = in.FailureThreshold
		}
		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create TCP monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_mail_monitor",
		Annotations: annWrite("Create mail posture monitor", false, false),
		Description: "Create an email deliverability monitor for a domain. Every check resolves MX, SPF (with the 10-lookup budget), DMARC, DKIM on common selectors, MTA-STS and TLS-RPT, and queries Spamhaus, SpamCop, Barracuda, PSBL and UCEPROTECT for every mail server address plus the Spamhaus DBL for the domain. Alerts on missing SPF or DMARC, +all, SPF PermError, a blocklist listing, or a DMARC policy weaker than require_dmarc_policy; emits events when SPF or DMARC records change or a listing appears/clears.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createMailMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		if in.DisplayName == "" || in.Domain == "" {
			return errorResult("display_name and domain are required")
		}
		policy := strings.ToLower(strings.TrimSpace(in.RequireDmarcPolicy))
		switch policy {
		case "", "none", "quarantine", "reject":
		default:
			return errorResult("require_dmarc_policy must be none, quarantine or reject")
		}
		domain := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(in.Domain)), "https://"), "http://")
		domain = strings.TrimSuffix(strings.Split(domain, "/")[0], ".")
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "mail",
			"url":                    domain,
			"timeout_seconds":        30,
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 3600),
		}
		if policy != "" {
			payload["mail_require_dmarc_policy"] = policy
		}
		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create mail monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})

	// create_mcp_monitor deliberately has no counterpart that accepts a
	// changed tool surface: approving a new baseline is human-only (web app
	// session), because an agent must not be able to approve the tool
	// changes that would steer it. The API refuses it for API keys and MCP
	// callers too. Do not add an accept/approve baseline tool here.
	mcpAnn := annWrite("Create MCP server monitor", false, false)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "create_mcp_monitor",
		Annotations: mcpAnn,
		Description: "Create a monitor for a remote MCP server (Streamable HTTP or legacy SSE). Each check runs the MCP handshake and tools/list (following pagination) and never calls a tool. It fingerprints every tool, lints tool text for poisoning patterns (hidden Unicode, injected instructions, sensitive file paths, cross-tool steering, encoded blobs) and records handshake and list latency. The first tool list seen becomes the approved baseline. Any later change to the tool set, a tool's description, title, schema or safety annotations, or the server instructions fails the check and keeps alerting until a person reviews and accepts it in the AlertKick web app; accepting changes cannot be done over MCP or with an API key. drift_policy 'record' logs changes as events without failing. auth_mode 'header' sends static headers (stored encrypted); 'oauth' checks only the server's OAuth discovery chain (401 challenge, protected-resource and authorization-server metadata, issuer match, PKCE S256, client registration) because OAuth login is not supported yet, so the tool list is not checked in that mode.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, in createMCPMonitorInput) (*mcp.CallToolResult, any, error) {
		if res, out, gerr := requireWrite(c); res != nil {
			return res, out, gerr
		}
		endpoint := strings.TrimSpace(in.URL)
		if in.DisplayName == "" || endpoint == "" {
			return errorResult("display_name and url are required")
		}
		if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errorResult("url must be the MCP endpoint as an http(s) URL, e.g. https://mcp.example.com/mcp")
		}
		transport := strings.ToLower(strings.TrimSpace(defaultString(in.Transport, "streamable-http")))
		switch transport {
		case "streamable-http", "sse":
		default:
			return errorResult("transport must be streamable-http or sse")
		}
		authMode := strings.ToLower(strings.TrimSpace(in.AuthMode))
		if authMode == "" {
			authMode = "none"
			if len(in.Headers) > 0 {
				authMode = "header"
			}
		}
		switch authMode {
		case "none", "oauth":
			if len(in.Headers) > 0 {
				return errorResult("headers are only used with auth_mode header")
			}
		case "header":
			if len(in.Headers) == 0 {
				return errorResult("auth_mode header needs at least one entry in headers (e.g. Authorization or X-API-Key)")
			}
		default:
			return errorResult("auth_mode must be none, header or oauth")
		}
		driftPolicy := strings.ToLower(strings.TrimSpace(defaultString(in.DriftPolicy, "alert")))
		switch driftPolicy {
		case "alert", "record":
		default:
			return errorResult("drift_policy must be alert or record")
		}
		if in.MaxTools < 0 {
			return errorResult("max_tools must be 0 (no cap) or more")
		}
		payload := map[string]interface{}{
			"display_name":           in.DisplayName,
			"monitor_type":           "mcp",
			"url":                    endpoint,
			"timeout_seconds":        defaultInt(in.TimeoutSeconds, 20),
			"check_interval_seconds": defaultInt(in.CheckIntervalSeconds, 600),
			"mcp_transport":          transport,
			"mcp_auth_mode":          authMode,
			"mcp_drift_policy":       driftPolicy,
		}
		if authMode == "header" {
			payload["mcp_headers"] = in.Headers
		}
		var expected []string
		for _, t := range in.ExpectedTools {
			if t = strings.TrimSpace(t); t != "" {
				expected = append(expected, t)
			}
		}
		if len(expected) > 0 {
			payload["mcp_expected_tools"] = expected
		}
		if in.MaxTools > 0 {
			payload["mcp_max_tools"] = in.MaxTools
		}
		if len(in.Locations) > 0 {
			payload["locations"] = in.Locations
		}
		data, err := c.CreateMonitor(payload)
		if err != nil {
			return errorResult("Failed to create MCP server monitor: " + err.Error())
		}
		return textResult(string(data) + uiLinkLine(c, data, "/monitors/"))
	})
}
