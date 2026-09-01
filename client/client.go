package client

import (
	"alertkick-mcp/config"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	version    string

	// Hosted-connector (http) mode: requests go to the internal api with
	// the tenant addressed via Host header and the caller's OAuth access
	// token forwarded as the credential. publicBaseURL is what we show to
	// users (ping commands etc.) — never the internal URL.
	bearerToken   string
	hostOverride  string
	publicBaseURL string
	writeAllowed  bool
}

func NewClient(cfg *config.Config, version string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:      cfg.APIURL + "/api/v1",
		apiKey:       cfg.APIKey,
		version:      version,
		writeAllowed: true, // stdio API keys carry the owning user's full access
	}
}

// NewTenantClient returns a client bound to one authenticated hosted-mode
// request: tenant from the verified token, credential = the token itself
// (the api re-verifies it and enforces tenant + grant liveness).
func NewTenantClient(cfg *config.Config, version, tenant, bearerToken string, writeAllowed bool) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL:       cfg.InternalAPIURL + "/api/v1",
		bearerToken:   bearerToken,
		hostOverride:  tenant + "." + cfg.TenantDomain,
		publicBaseURL: "https://" + tenant + "." + cfg.TenantDomain + "/api/v1",
		version:       version,
		writeAllowed:  writeAllowed,
	}
}

// CanWrite reports whether this connection may call write tools.
func (c *Client) CanWrite() bool { return c.writeAllowed }

// APIError is what doJSON returns for any non-2xx response. Tools that
// want to turn a plan-limit 402 into a sentence a person can act on branch
// on Status with errors.As; everything else keeps using Error(), whose text
// is unchanged from before this type existed.
type APIError struct {
	Status int
	Body   []byte
	Method string
	Path   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API returned status %d: %s", e.Status, string(e.Body))
}

// PlanLimitError is the body the api sends with a 402 when a plan limit
// blocks a create (hosts/add, monitors/create, heartbeats/create) or when
// the workspace has no plan at all (subscription_required).
type PlanLimitError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	UpgradeURL string `json:"upgrade_url"`
	Usage      *struct {
		ResourceType string `json:"resource_type"`
		Current      int64  `json:"current"`
		Limit        int    `json:"limit"`
		LimitReached bool   `json:"limit_reached"`
		Unlimited    bool   `json:"unlimited"`
	} `json:"usage"`
}

// AsPlanLimit decodes a 402 body. ok is false for any other status or an
// undecodable body, so callers fall back to the raw error text.
func AsPlanLimit(err error) (*PlanLimitError, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusPaymentRequired {
		return nil, false
	}
	var pl PlanLimitError
	if jerr := json.Unmarshal(apiErr.Body, &pl); jerr != nil || pl.Error == "" {
		return nil, false
	}
	return &pl, true
}

func (c *Client) doJSON(method, path string, body interface{}, result interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	} else {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.hostOverride != "" {
		// Tenant routing in the api is Host-based; override it while the
		// TCP connection still goes to the internal URL.
		req.Host = c.hostOverride
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AlertKick-MCP/"+c.version)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		log.Printf("[client] %s %s returned %d: %s", method, path, resp.StatusCode, string(respBody))
		return &APIError{Status: resp.StatusCode, Body: respBody, Method: method, Path: path}
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

func (c *Client) doGet(path string, params url.Values, result interface{}) error {
	if len(params) > 0 {
		path = path + "?" + params.Encode()
	}
	return c.doJSON("GET", path, nil, result)
}

// Servers

func (c *Client) ListHosts(offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	var result json.RawMessage
	err := c.doGet("/hosts", params, &result)
	return result, err
}

func (c *Client) GetHost(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/hosts/"+uuid, nil, &result)
	return result, err
}

func (c *Client) GetHostContainers(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/hosts/"+uuid+"/containers", nil, &result)
	return result, err
}

// AddHost registers a server record and its agent token. The api answers
// 402 (agent_limit_reached) when the plan has no free server seat, which
// on the Free plan means zero seats: agent-based monitoring is a trial /
// paid-plan feature.
func (c *Client) AddHost(serverName, escalationPolicyUUID string) (json.RawMessage, error) {
	payload := map[string]interface{}{"server_name": serverName}
	if escalationPolicyUUID != "" {
		payload["escalation_policy_uuid"] = escalationPolicyUUID
	}
	var result json.RawMessage
	err := c.doJSON("POST", "/hosts/add", payload, &result)
	return result, err
}

// InstallInstruction mirrors the api's install-instructions item: Command
// is the one-liner for Linux, Content is a full script (Windows).
type InstallInstruction struct {
	Heading string `json:"heading"`
	Command string `json:"command"`
	Content string `json:"content"`
}

type AgentInstallInstructions struct {
	Instructions []InstallInstruction `json:"instructions"`
}

// GetUniversalInstallCommand returns the OS-detecting `curl | sh` install
// command for a host. The signed URL inside it is valid for 24 hours; call
// again for a fresh one.
func (c *Client) GetUniversalInstallCommand(hostUUID string) (*AgentInstallInstructions, error) {
	var result AgentInstallInstructions
	err := c.doGet("/hosts/"+hostUUID+"/agent-install-universal", nil, &result)
	return &result, err
}

// BillingUsage is the subset of GET /billing/usage the tools need to tell
// a user which plan they are on and how many seats remain.
type BillingUsage struct {
	Usage map[string]struct {
		Current   int64 `json:"current"`
		Limit     int   `json:"limit"`
		Unlimited bool  `json:"unlimited"`
	} `json:"usage"`
	Plan struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"plan"`
}

func (c *Client) GetBillingUsage() (*BillingUsage, error) {
	var result BillingUsage
	err := c.doGet("/billing/usage", nil, &result)
	return &result, err
}

// Alerts

func (c *Client) ListAlerts(status string, offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	if status != "" {
		params.Set("status", status)
	}
	var result json.RawMessage
	err := c.doGet("/alerts", params, &result)
	return result, err
}

func (c *Client) GetAlert(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/alerts/"+uuid, nil, &result)
	return result, err
}

func (c *Client) AcknowledgeAlerts(uuids []string) (json.RawMessage, error) {
	body := map[string]interface{}{"UUIDs": uuids}
	var result json.RawMessage
	err := c.doJSON("POST", "/alerts/acknowledge", body, &result)
	return result, err
}

func (c *Client) ResolveAlerts(uuids []string) (json.RawMessage, error) {
	body := map[string]interface{}{"UUIDs": uuids}
	var result json.RawMessage
	err := c.doJSON("POST", "/alerts/resolve", body, &result)
	return result, err
}

// Security Events

func (c *Client) ListSecurityEvents(params url.Values) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/security-events", params, &result)
	return result, err
}

func (c *Client) GetSecurityEventsStats(duration string) (json.RawMessage, error) {
	params := url.Values{}
	if duration != "" {
		params.Set("duration", duration)
	}
	var result json.RawMessage
	err := c.doGet("/security-events/stats", params, &result)
	return result, err
}

// Monitors

func (c *Client) ListMonitors(offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	var result json.RawMessage
	err := c.doGet("/monitors/all", params, &result)
	return result, err
}

func (c *Client) GetMonitor(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/monitors/"+uuid, nil, &result)
	return result, err
}

// Monitor write operations

// ListPollerLocations returns the system + customer poller locations visible
// to the account (GET /poller-locations/all).
func (c *Client) ListPollerLocations() (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("GET", "/poller-locations/all", nil, &result)
	return result, err
}

func (c *Client) CreateMonitor(payload map[string]interface{}) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/monitors/create", payload, &result)
	return result, err
}

func (c *Client) PauseMonitor(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/monitors/"+uuid+"/pause", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) ResumeMonitor(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/monitors/"+uuid+"/resume", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) DeleteMonitor(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("DELETE", "/monitors/"+uuid, nil, &result)
	return result, err
}

// Heartbeats

func (c *Client) ListHeartbeats(offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	var result json.RawMessage
	err := c.doGet("/heartbeats/all", params, &result)
	return result, err
}

func (c *Client) GetHeartbeat(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/heartbeats/"+uuid, nil, &result)
	return result, err
}

// AutoPingResponse mirrors the API's auto-provisioning ping response.
type AutoPingResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	UUID    string `json:"uuid"`
	Slug    string `json:"slug"`
	Created bool   `json:"created"`
}

// AutoPingHeartbeat pings /hb/auto/{slug}, creating the heartbeat on
// first ping. interval/grace/name apply only when it is created.
func (c *Client) AutoPingHeartbeat(slug string, intervalSeconds, graceSeconds int, name string) (*AutoPingResponse, error) {
	params := url.Values{}
	if intervalSeconds > 0 {
		params.Set("interval", fmt.Sprintf("%d", intervalSeconds))
	}
	if graceSeconds > 0 {
		params.Set("grace", fmt.Sprintf("%d", graceSeconds))
	}
	if name != "" {
		params.Set("name", name)
	}
	path := "/hb/auto/" + url.PathEscape(slug)
	if len(params) > 0 {
		path = path + "?" + params.Encode()
	}
	var result AutoPingResponse
	err := c.doJSON("GET", path, nil, &result)
	return &result, err
}

func (c *Client) EnableHeartbeat(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/heartbeats/"+uuid+"/enable", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) DisableHeartbeat(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/heartbeats/"+uuid+"/disable", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) DeleteHeartbeat(uuid string) (json.RawMessage, error) {
	body := map[string]interface{}{"uuid": uuid}
	var result json.RawMessage
	err := c.doJSON("POST", "/heartbeats/delete", body, &result)
	return result, err
}

// BaseURL returns the API base URL (including /api/v1), for composing
// ping command examples in tool output.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// PublicBaseURL returns the user-facing API base URL (including /api/v1).
// In hosted mode the request URL is internal, so anything shown to users
// (heartbeat ping commands, links) must use this instead of BaseURL.
func (c *Client) PublicBaseURL() string {
	if c.publicBaseURL != "" {
		return c.publicBaseURL
	}
	return c.baseURL
}

// Incidents

func (c *Client) ListIncidents(status, severity string, offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	if status != "" {
		params.Set("status", status)
	}
	if severity != "" {
		params.Set("severity", severity)
	}
	var result json.RawMessage
	err := c.doGet("/incidents/all", params, &result)
	return result, err
}

func (c *Client) GetIncident(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/incidents/"+uuid, nil, &result)
	return result, err
}

// Changes

func (c *Client) ListChanges(status, hostUUID string, offset, limit int) (json.RawMessage, error) {
	params := url.Values{}
	params.Set("offset", fmt.Sprintf("%d", offset))
	params.Set("limit", fmt.Sprintf("%d", limit))
	if status != "" {
		params.Set("status", status)
	}
	if hostUUID != "" {
		params.Set("host_uuid", hostUUID)
	}
	var result json.RawMessage
	err := c.doGet("/changes/all", params, &result)
	return result, err
}

func (c *Client) GetChange(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doGet("/changes/"+uuid, nil, &result)
	return result, err
}

func (c *Client) CreateChange(title, description, windowStart, windowEnd string, hostUUIDs []string) (json.RawMessage, error) {
	body := map[string]interface{}{
		"title":        title,
		"description":  description,
		"window_start": windowStart,
		"window_end":   windowEnd,
		"host_uuids":   hostUUIDs,
	}
	var result json.RawMessage
	err := c.doJSON("POST", "/changes/create", body, &result)
	return result, err
}

func (c *Client) ApproveChange(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/changes/"+uuid+"/approve", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) StartChange(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/changes/"+uuid+"/start", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) CompleteChange(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/changes/"+uuid+"/complete", map[string]interface{}{}, &result)
	return result, err
}

func (c *Client) VerifyChange(uuid string) (json.RawMessage, error) {
	var result json.RawMessage
	err := c.doJSON("POST", "/changes/"+uuid+"/verify", map[string]interface{}{}, &result)
	return result, err
}

// PublicUIBaseURL returns the user-facing web UI base URL (no /api/v1),
// for "view it in AlertKick" links in tool output.
func (c *Client) PublicUIBaseURL() string {
	return strings.TrimSuffix(c.PublicBaseURL(), "/api/v1")
}
