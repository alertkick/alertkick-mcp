package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config drives both run modes:
//
//   - stdio (default): the classic per-user local binary. Requires APIKey;
//     APIURL points at the user's tenant, e.g. https://acme.alertkick.com.
//
//   - http: the hosted multi-tenant connector behind mcp.{domain}
//     (streamable HTTP + OAuth). Requires OAuthSigningKey (shared with the
//     api, which is the authorization server) and InternalAPIURL; per-request
//     tenant identity comes from the verified access token, and requests to
//     the api are addressed by Host header, never by API key.
//
// Design: fleet/docs/features/mcp-connector.md
type Config struct {
	APIKey string `json:"api_key"`
	APIURL string `json:"api_url"`

	// HTTP / hosted-connector mode.
	HTTPAddr        string `json:"http_addr"`         // e.g. ":9194"; non-empty selects http mode
	PublicURL       string `json:"public_url"`        // e.g. "https://mcp.alertkick.com" (issuer + PRM host)
	OAuthSigningKey string `json:"oauth_signing_key"` // HS256 key shared with the api (MCPOAuth.SigningKey)
	InternalAPIURL  string `json:"internal_api_url"`  // e.g. "http://api:9191"
	TenantDomain    string `json:"tenant_domain"`     // e.g. "alertkick.com"
	DocsURL         string `json:"docs_url"`          // advertised in protected-resource metadata
}

func DefaultConfig() *Config {
	return &Config{
		APIURL:         "https://app.alertkick.com",
		InternalAPIURL: "http://api:9191",
		TenantDomain:   "alertkick.com",
		DocsURL:        "https://docs.alertkick.com",
	}
}

// HTTPMode reports whether the hosted streamable-HTTP mode is selected.
func (c *Config) HTTPMode() bool { return c.HTTPAddr != "" }

// Resource returns the canonical MCP server URL (RFC 8707 audience).
func (c *Config) Resource() string { return c.PublicURL + "/mcp" }

func Load(configFile string) (*Config, error) {
	cfg := DefaultConfig()

	if configFile != "" {
		data, err := os.ReadFile(configFile)
		if err == nil {
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	if v := os.Getenv("ALERTKICK_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("ALERTKICK_API_URL"); v != "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("AKMCP_HTTP_ADDR"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("AKMCP_PUBLIC_URL"); v != "" {
		cfg.PublicURL = v
	}
	if v := os.Getenv("AKMCP_OAUTH_SIGNING_KEY"); v != "" {
		cfg.OAuthSigningKey = v
	}
	if v := os.Getenv("AKMCP_INTERNAL_API_URL"); v != "" {
		cfg.InternalAPIURL = v
	}
	if v := os.Getenv("AKMCP_TENANT_DOMAIN"); v != "" {
		cfg.TenantDomain = v
	}
	if v := os.Getenv("AKMCP_DOCS_URL"); v != "" {
		cfg.DocsURL = v
	}

	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	cfg.PublicURL = strings.TrimRight(cfg.PublicURL, "/")
	cfg.InternalAPIURL = strings.TrimRight(cfg.InternalAPIURL, "/")

	if cfg.HTTPMode() {
		if cfg.OAuthSigningKey == "" {
			return nil, fmt.Errorf("AKMCP_OAUTH_SIGNING_KEY is required in http mode")
		}
		if cfg.PublicURL == "" {
			return nil, fmt.Errorf("AKMCP_PUBLIC_URL is required in http mode (e.g. https://mcp.alertkick.com)")
		}
		return cfg, nil
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("ALERTKICK_API_KEY is required (set env var or use -config file)")
	}

	return cfg, nil
}
