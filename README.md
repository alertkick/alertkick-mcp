# AlertKick MCP Server

An open-source [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server that connects AI tools like Claude, Cursor, and others to the [AlertKick](https://alertkick.com) monitoring platform.

Two ways to use it:

- **Hosted connector (recommended)** — `https://mcp.alertkick.com/mcp`, remote streamable HTTP with one-click OAuth. Nothing to install.
- **Local binary (stdio)** — run `akmcp` yourself with an API key.

## Hosted connector (OAuth)

Add a custom connector in Claude (Settings → Connectors → Add custom connector) with the URL:

```
https://mcp.alertkick.com/mcp
```

Claude opens the AlertKick consent flow in your browser: pick your workspace, sign in, approve. No API keys involved; disconnect any time from Claude or by revoking the connection in AlertKick.

Claude Code:

```bash
claude mcp add --transport http alertkick https://mcp.alertkick.com/mcp
```

The hosted connector implements the MCP authorization spec (OAuth 2.1, PKCE S256, dynamic client registration and client-ID metadata documents, RFC 8414/9728 discovery), so any spec-compliant MCP client can connect the same way.

## Local binary (stdio)

```
AI Tool (Claude Desktop / Cursor / etc.)
    |  stdio (JSON-RPC)
    v
  akmcp (local binary)
    |  HTTPS + X-API-Key header
    v
  AlertKick API
```

## Quick Start (local binary)

1. Download the latest release for your platform, or [build from source](#build-from-source).

2. Get your API key from **AlertKick → Settings → API Keys**.

3. Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "alertkick": {
      "command": "/path/to/akmcp",
      "env": {
        "ALERTKICK_API_KEY": "ak_your_key_here",
        "ALERTKICK_API_URL": "https://yourworkspace.alertkick.com"
      }
    }
  }
}
```

4. Restart Claude Desktop. You should see 34 AlertKick tools available.

### Claude Code

```bash
claude mcp add --transport stdio alertkick \
  --env ALERTKICK_API_KEY=ak_your_key_here \
  --env ALERTKICK_API_URL=https://yourworkspace.alertkick.com \
  -- /path/to/akmcp
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ALERTKICK_API_KEY` | Yes (stdio mode) | — | Your API key (`ak_…`) |
| `ALERTKICK_API_URL` | Yes (stdio mode) | `https://app.alertkick.com` | Your workspace URL, e.g. `https://yourworkspace.alertkick.com` — API keys are workspace-scoped, so the default only works for the `app` workspace |

You can also use a JSON config file with `-config path/to/config.json`:

```json
{
  "api_key": "ak_your_key_here",
  "api_url": "https://yourworkspace.alertkick.com"
}
```

Environment variables take priority over the config file.

### Hosted (HTTP) mode variables

Used only when self-hosting the multi-tenant connector (this is what runs mcp.alertkick.com — not needed for normal use):

| Variable | Description |
|----------|-------------|
| `AKMCP_HTTP_ADDR` | Listen address, e.g. `:9194`. Non-empty selects HTTP mode |
| `AKMCP_PUBLIC_URL` | Public issuer URL, e.g. `https://mcp.alertkick.com` |
| `AKMCP_OAUTH_SIGNING_KEY` | HS256 key shared with the AlertKick API (`MCPOAuth.SigningKey`) |
| `AKMCP_INTERNAL_API_URL` | Internal API base, e.g. `http://api:9191` |
| `AKMCP_TENANT_DOMAIN` | Base domain for tenant hosts, e.g. `alertkick.com` |
| `AKMCP_DOCS_URL` | Documentation URL advertised in metadata |

## Tools

### Servers
| Tool | Description |
|------|-------------|
| `add_server` | Register a server for agent-based monitoring and get the one-line install command (trial and paid plans; the Free plan has no server seats) |
| `get_server_install_command` | Fetch the install command again for a server whose agent is not reporting yet |
| `list_servers` | List all monitored servers with status, hostname, OS info |
| `get_server` | Get detailed info for a specific server |
| `get_server_containers` | Get Docker containers running on a server |

### Alerts
| Tool | Description |
|------|-------------|
| `list_alerts` | List alerts with optional status filter |
| `get_alert` | Get detailed info for a specific alert |
| `acknowledge_alert` | Acknowledge an open alert |
| `resolve_alert` | Resolve an alert |

### Security Events
| Tool | Description |
|------|-------------|
| `list_security_events` | List eBPF security detections with filters |
| `get_security_event_stats` | Get aggregate security event statistics |

### Monitors
| Tool | Description |
|------|-------------|
| `list_monitors` | List HTTP/TCP/DNS/SSL monitors |
| `get_monitor` | Get detailed info for a specific monitor |
| `list_poller_locations` | List the poller locations monitors can run from (system regions + your own pollers) |
| `create_monitor` | Generic creator (http, api, dns, tcp, domain expiry, or mail); all creators accept optional `locations` |
| `create_https_monitor` | Create a website/API uptime monitor with TLS certificate expiry alerts |
| `create_dns_monitor` | Create a DNS resolution / answer-change monitor |
| `create_domain_expiry_monitor` | Create a domain registration expiry monitor (RDAP) |
| `create_tcp_monitor` | Create a TCP port monitor |
| `create_mail_monitor` | Create an email deliverability monitor (MX, SPF, DMARC, DKIM, MTA-STS, blocklists) |
| `pause_monitor` | Pause a monitor's checks and alerting |
| `resume_monitor` | Resume a paused monitor |
| `delete_monitor` | Permanently delete a monitor |

### Heartbeats
| Tool | Description |
|------|-------------|
| `list_heartbeats` | List heartbeat monitors for cron jobs |
| `get_heartbeat` | Get a heartbeat's configuration, ping key, and health |
| `create_heartbeat` | Create a heartbeat for a cron job (idempotent by slug) and get its ping command |
| `enable_heartbeat` | Enable a disabled heartbeat |
| `disable_heartbeat` | Disable a heartbeat's alerting |
| `delete_heartbeat` | Permanently delete a heartbeat |

### Incidents
| Tool | Description |
|------|-------------|
| `list_incidents` | List incidents with status/severity filters |
| `get_incident` | Get detailed info for a specific incident |

### Change Management
| Tool | Description |
|------|-------------|
| `list_changes` | List change requests with status/host filters |
| `get_change` | Get detailed info for a specific change |
| `create_change` | Create a change request with a maintenance window and target servers |
| `approve_change` | Approve a requested change |
| `start_change` | Start a change, opening a maintenance window (SSH unlock) on its servers |
| `complete_change` | Complete a change, re-locking servers and triggering FIM verification |
| `verify_change` | Re-run FIM verification for a completed change |

## Example Prompts

- "List my servers and show any that are offline"
- "Show me all open alerts"
- "What security events happened in the last hour?"
- "Acknowledge alert abc-123"
- "Give me a summary of my monitoring infrastructure"
- "Set up a heartbeat for my nightly backup cron job"
- "Monitor https://example.com and alert if the TLS cert is close to expiry"
- "Watch example.com for domain registration expiry"

## Build from Source

Requires Go 1.24+.

```bash
git clone https://github.com/alertkick/alertkick-mcp.git
cd alertkick-mcp
make build
./akmcp --version
```

## Docker

```bash
docker build -t akmcp .
docker run -e ALERTKICK_API_KEY=ak_... akmcp
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
