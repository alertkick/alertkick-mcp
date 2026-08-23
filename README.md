# AlertKick MCP Server

An open-source [MCP](https://modelcontextprotocol.io/) (Model Context Protocol) server that connects AI tools like Claude Desktop, Cursor, and others to the [AlertKick](https://alertkick.com) monitoring platform.

```
AI Tool (Claude Desktop / Cursor / etc.)
    |  stdio (JSON-RPC)
    v
  akmcp (local binary)
    |  HTTPS + X-API-Key header
    v
  AlertKick API
```

## Quick Start

1. Download the latest release for your platform, or [build from source](#build-from-source).

2. Get your API key from **AlertKick → Settings → API Keys**.

3. Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "alertkick": {
      "command": "/path/to/akmcp",
      "env": {
        "ALERTKICK_API_KEY": "ak_your_key_here"
      }
    }
  }
}
```

4. Restart Claude Desktop. You should see 30 AlertKick tools available.

### Claude Code

```bash
claude mcp add --transport stdio alertkick \
  --env ALERTKICK_API_KEY=ak_your_key_here \
  -- /path/to/akmcp
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ALERTKICK_API_KEY` | Yes | — | Your API key (`ak_...`) |
| `ALERTKICK_API_URL` | No | `https://app.alertkick.com` | API base URL |

You can also use a JSON config file with `-config path/to/config.json`:

```json
{
  "api_key": "ak_your_key_here",
  "api_url": "https://app.alertkick.com"
}
```

Environment variables take priority over the config file.

## Tools

### Servers
| Tool | Description |
|------|-------------|
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
| `create_monitor` | Create an uptime monitor (http, api, dns, tcp, or domain expiry) |
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
