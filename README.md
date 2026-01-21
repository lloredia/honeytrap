<p align="center">
  <h1 align="center">🍯 HONEYTRAP</h1>
  <p align="center">
    <em>Uncover Threats Faster, Stay One Step Ahead</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/github/last-commit/lloredia/honeytrap?style=flat&logo=git&logoColor=white&color=0080ff" alt="last-commit">
  <img src="https://img.shields.io/github/languages/top/lloredia/honeytrap?style=flat&color=0080ff" alt="repo-top-language">
  <img src="https://img.shields.io/github/languages/count/lloredia/honeytrap?style=flat&color=0080ff" alt="repo-language-count">
  <img src="https://img.shields.io/github/license/lloredia/honeytrap?style=flat&color=0080ff" alt="license">
</p>

<p align="center">
  <em>Built with the tools and technologies:</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000.svg?style=flat&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Tokio-463B3B.svg?style=flat&logo=rust&logoColor=white" alt="Tokio">
  <img src="https://img.shields.io/badge/Docker-2496ED.svg?style=flat&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/Prometheus-E6522C.svg?style=flat&logo=prometheus&logoColor=white" alt="Prometheus">
  <img src="https://img.shields.io/badge/Grafana-F46800.svg?style=flat&logo=grafana&logoColor=white" alt="Grafana">
  <img src="https://img.shields.io/badge/ClickHouse-FFCC01.svg?style=flat&logo=clickhouse&logoColor=black" alt="ClickHouse">
  <img src="https://img.shields.io/badge/JSON-000000.svg?style=flat&logo=json&logoColor=white" alt="JSON">
  <img src="https://img.shields.io/badge/Markdown-000000.svg?style=flat&logo=markdown&logoColor=white" alt="Markdown">
</p>


## Overview

HoneyTrap is a modular honeypot system designed to capture, log, and analyze malicious activity. It simulates vulnerable services to attract attackers and records their every move - from login attempts to shell commands.

## Architecture

```mermaid
flowchart TB
    subgraph Internet
        A[Attacker]
    end

    subgraph HoneyTrap Network
        subgraph Honeypots
            SSH[SSH Honeypot<br/>Port 2222]
        end

        subgraph Core Services
            COL[Collector]
            PROM[Prometheus<br/>Port 9090]
        end

        subgraph Storage
            CH[(ClickHouse)]
            JSONL[events.jsonl]
        end

        subgraph Visualization
            GRAF[Grafana<br/>Port 3000]
        end
    end

    A -->|SSH Connection| SSH
    SSH -->|Events| JSONL
    SSH -->|Events| COL
    SSH -->|Metrics| PROM
    COL -->|Store| CH
    PROM -->|Query| GRAF
    CH -->|Query| GRAF
```

## Event Flow

```mermaid
sequenceDiagram
    participant Attacker
    participant SSH Honeypot
    participant Event Processor
    participant Storage

    Attacker->>SSH Honeypot: TCP Connection
    SSH Honeypot->>Event Processor: Connection Event
    Event Processor->>Storage: Log to events.jsonl

    Attacker->>SSH Honeypot: Auth (root/password123)
    SSH Honeypot->>Event Processor: Auth Event (credentials captured)
    Event Processor->>Storage: Log credentials

    Attacker->>SSH Honeypot: Command (whoami)
    SSH Honeypot-->>Attacker: root
    SSH Honeypot->>Event Processor: Command Event
    Event Processor->>Storage: Log command

    Attacker->>SSH Honeypot: Command (cat /etc/passwd)
    SSH Honeypot-->>Attacker: Fake passwd file
    SSH Honeypot->>Event Processor: Command Event
    Event Processor->>Storage: Log command
```

## Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Language** | Rust 🦀 | Memory-safe, high-performance core |
| **Async Runtime** | Tokio | Handles thousands of concurrent connections |
| **SSH Protocol** | russh | SSH server implementation |
| **Serialization** | Serde + JSON | Event formatting and storage |
| **Metrics** | Prometheus | Real-time monitoring |
| **Visualization** | Grafana | Dashboards and alerting |
| **Database** | ClickHouse | High-speed analytics storage |
| **Containerization** | Docker | Easy deployment |

## Project Structure

```mermaid
graph LR
    subgraph Workspace
        ROOT[honeytrap/]
        ROOT --> SHARED[shared/]
        ROOT --> HONEYPOTS[honeypots/]
        ROOT --> COLLECTOR[collector/]
        
        SHARED --> |Common Types| EVENTS[events.rs]
        SHARED --> |IOC Types| IOC[ioc.rs]
        
        HONEYPOTS --> SSH[ssh/]
        SSH --> SERVER[server.rs]
        SSH --> HANDLER[handler.rs]
        SSH --> SESSION[session.rs]
        SSH --> CONFIG[config.rs]
        
        COLLECTOR --> CLICKHOUSE[clickhouse.rs]
    end
```

```
honeytrap/
├── Cargo.toml              # Workspace configuration
├── docker-compose.yml      # Full stack deployment
├── shared/                 # Shared library
│   └── src/
│       ├── lib.rs          # Event types, protocols
│       └── ioc.rs          # Indicators of Compromise
├── honeypots/
│   └── ssh/                # SSH Honeypot
│       └── src/
│           ├── main.rs     # Entry point
│           ├── server.rs   # SSH server & event processor
│           ├── handler.rs  # Connection handler
│           ├── session.rs  # Session state management
│           └── config.rs   # Configuration
└── collector/              # Event collector service
    └── src/
        ├── main.rs
        └── clickhouse.rs   # ClickHouse integration
```

## Quick Start

### Prerequisites

- Rust 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Docker & Docker Compose (optional, for full stack)

### Build & Run

```bash
# Clone the repository
git clone https://github.com/lloredia/honeytrap.git
cd honeytrap

# Build release binary
cargo build --release

# Run SSH honeypot
cargo run -p honeytrap-ssh -- --port 2222
```

### Test the Honeypot

```bash
# From another terminal
ssh root@localhost -p 2222
# Enter any password - all credentials are captured!

# Try some commands in the fake shell
whoami
ls -la
cat /etc/passwd
```

### View Captured Events

```bash
cat events.jsonl | jq .
```

## Event Types

```mermaid
classDiagram
    class HoneypotEvent {
        +UUID id
        +UUID session_id
        +DateTime timestamp
        +Protocol protocol
        +EventCategory category
        +Severity severity
        +SourceInfo source
        +DestinationInfo destination
        +Credentials credentials
        +Command command
        +Vec~String~ tags
    }

    class EventCategory {
        <<enumeration>>
        Connection
        Authentication
        Command
        FileAccess
        NetworkActivity
    }

    class Severity {
        <<enumeration>>
        Low
        Medium
        High
        Critical
    }

    HoneypotEvent --> EventCategory
    HoneypotEvent --> Severity
```

### Sample Event Output

```json
{
  "id": "d42cbef9-7328-407f-b2f4-0dd9a1cadaf0",
  "session_id": "f97f3ea1-fab7-4c70-964f-902b533457ff",
  "timestamp": "2026-01-21T09:36:42.745Z",
  "protocol": "ssh",
  "category": "authentication",
  "severity": "high",
  "source": {
    "ip": "192.168.1.100",
    "port": 58719
  },
  "destination": {
    "ip": "0.0.0.0",
    "port": 2222,
    "honeypot_id": "ssh-01"
  },
  "credentials": {
    "username": "root",
    "password": "admin123",
    "auth_method": "password",
    "success": true
  },
  "tags": ["password_auth"]
}
```

## Docker Deployment

### Full Stack

```bash
# Start SSH Honeypot + Prometheus + Grafana
docker-compose up -d
```

| Service | URL | Credentials |
|---------|-----|-------------|
| SSH Honeypot | `ssh root@localhost -p 2222` | any password |
| Prometheus | http://localhost:9090 | - |
| Grafana | http://localhost:3000 | admin / admin |

### With ClickHouse Analytics

```bash
docker-compose -f docker-compose_clickhouse.yml up -d
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `RUST_LOG` | `info` | Log level (debug, info, warn, error) |
| `SSH_PORT` | `2222` | SSH honeypot listen port |
| `METRICS_PORT` | `9100` | Prometheus metrics port |

### CLI Options

```bash
honeytrap-ssh --help

Options:
  --host <HOST>    Listen address [default: 0.0.0.0]
  --port <PORT>    SSH port [default: 2222]
  -h, --help       Print help
```

## Metrics

Prometheus metrics exposed at `:9100/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `honeytrap_events_captured_total` | Counter | Total events by category |
| `honeytrap_active_sessions` | Gauge | Current active sessions |
| `honeytrap_auth_attempts_total` | Counter | Authentication attempts |

## Security Considerations

> ⚠️ **Warning**: Honeypots intentionally attract malicious traffic. Deploy responsibly.

- Run in an isolated network/VM
- Never expose your real services on the same host
- Monitor resource usage (attackers may attempt DoS)
- Regularly review captured data for actionable intelligence

## Roadmap

- [x] SSH Honeypot
- [x] Credential capture
- [x] Command logging
- [x] Prometheus metrics
- [x] JSON event logging
- [ ] HTTP/HTTPS Honeypot
- [ ] Telnet Honeypot
- [ ] FTP Honeypot
- [ ] GeoIP enrichment
- [ ] Real-time alerting
- [ ] Web UI dashboard

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [russh](https://github.com/warp-tech/russh) - Rust SSH implementation
- [Tokio](https://tokio.rs/) - Async runtime for Rust
- [Cowrie](https://github.com/cowrie/cowrie) - Inspiration for SSH honeypot features

---

**Made with 🦀 and 🍯 by [lloredia](https://github.com/lloredia)**






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
