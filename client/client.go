package client

import (
	"alertkick-mcp/config"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	version    string
}

func NewClient(cfg *config.Config, version string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: cfg.APIURL + "/api/v1",
		apiKey:  cfg.APIKey,
		version: version,
	}
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

	req.Header.Set("X-API-Key", c.apiKey)
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
		return fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(respBody))
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
