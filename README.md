# HoneyTrap 🍯

A distributed honeypot network for capturing attacker behavior. Built with Rust.

## Quick Start

```bash
# Build
cargo build --release

# Run SSH honeypot
cargo run -p honeytrap-ssh -- --port 2222

# Test it (from another terminal)
ssh root@localhost -p 2222
# Try any password - it accepts all credentials
```

## Features

- **SSH Honeypot**: Fake shell captures credentials and commands
- **Event Logging**: JSON events to `events.jsonl`
- **Metrics**: Prometheus metrics on port 9100
- **Docker Support**: Full stack with Prometheus & Grafana

## SSH Honeypot

Captures:
- Login credentials (username/password)
- SSH public keys
- Shell commands
- Session metadata

Fake shell supports: `ls`, `cd`, `cat`, `whoami`, `id`, `uname`, `ps`, `netstat`, `wget`, `curl`, and more.

## Event Output

Events are written to `events.jsonl` in JSON Lines format:

```json
{
  "id": "d42cbef9-7328-407f-b2f4-0dd9a1cadaf0",
  "session_id": "f97f3ea1-fab7-4c70-964f-902b533457ff",
  "timestamp": "2026-01-21T09:36:36.139Z",
  "protocol": "ssh",
  "category": "authentication",
  "severity": "high",
  "source": {"ip": "127.0.0.1", "port": 58719},
  "credentials": {"username": "root", "password": "root", "auth_method": "password"}
}
```

## Architecture

```
honeytrap/
├── shared/           # Common types (events, IOCs)
├── collector/        # Event collector service
└── honeypots/
    └── ssh/          # SSH honeypot
```

## Docker Deployment

### Full Stack (SSH + Prometheus + Grafana)
```bash
docker-compose up -d
```

Access:
- SSH Honeypot: `ssh root@localhost -p 2222`
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)

### With ClickHouse Analytics
```bash
docker-compose -f docker-compose_clickhouse.yml up -d
```

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` | Listen address |
| `--port` | `2222` | SSH port |

## Production Deployment

1. Deploy on a VPS/cloud server
2. Use port 22 for maximum traffic (move real SSH elsewhere)
3. Set up firewall rules to allow inbound SSH
4. Monitor with Grafana dashboards

## License

MIT
